# shellcheck shell=bash
# Per-run identity for the lifecycle E2E harnesses, and the collection of
# what a killed run leaves behind.
#
# Two lifecycle runs could not share a machine.  Every run brought the
# stack up under the default Compose project, the default install
# identity and the default published ports, so a second run — another
# worktree, another agent session, a developer checking something by hand
# — collided with the first on the project, on container names and on
# `127.0.0.1` ports, and the collision surfaced as a verify timeout or a
# container-name error far from its cause.
#
# What this library gives a harness is one identity per run, derived from
# the run identifier its artifact directory is already named after, plus
# the liveness bookkeeping that unique naming makes necessary.
#
# The identity and the Compose project are one string, and necessarily
# so.  `infra install --instance-name X` resolves through
# `ComposeIdentity::for_instance` (`src/commands/compose_project.rs`),
# whose project *is* the instance name, and every later `bootroot`
# invocation resolves its project from the `BOOTROOT_INSTANCE` the
# install recorded in `.env`.  A harness that used some other project for
# its own raw `docker compose` calls would tear down a project holding
# none of its containers.  The two values are therefore derived through
# separate functions with separate rules — the instance is validated and
# length-bounded, the project is not — and `assert_resolved_compose_
# project` in each harness reads the resolved project back off a real
# container rather than assuming it.
#
# Requires `lib/leftovers.sh` for `BOOTROOT_CONTAINER_SUFFIXES` and
# `bootroot_leftover_containers`, and a caller-defined `fail`.

# `MAX_INSTANCE_NAME_LEN` in src/commands/compose_project.rs: the
# DNS-label budget left over after the longest container-name suffix.
# `validate_instance_name` rejects anything longer rather than
# normalising it, so an over-long derived name fails `infra install`
# outright.
BOOTROOT_MAX_INSTANCE_NAME_LEN=39

# Directory holding one liveness marker per live E2E run.
#
# Under `${TMPDIR:-/tmp}` because that is where the harness already keeps
# run state (`scripts/preflight/ci/e2e-matrix.sh`), and because on macOS
# it is per-user, which keeps one user's markers out of another's sweep.
BOOTROOT_E2E_RUN_MARKER_DIR="${BOOTROOT_E2E_RUN_MARKER_DIR:-${TMPDIR:-/tmp}/bootroot-e2e-runs}"

# The characters `validate_instance_name` accepts after the prefix,
# spelled out rather than written as `a-z0-9`.  A bracket range is
# collated by the caller's locale, and under most of them `[a-z]` matches
# `E` — which would let an uppercase name through the guard below and
# have `infra install` reject it several minutes into a run.
RUN_SCOPE_INSTANCE_ALPHABET="abcdefghijklmnopqrstuvwxyz0123456789"

# Reduces a free-form run identifier to the alphabet an instance name may
# use, dropping every other character rather than mapping it to `-`: the
# result is a token to be appended to a prefix, and a mapped separator
# would spend the length budget on punctuation.
run_scope_sanitize() {
  printf '%s' "$1" \
    | LC_ALL=C tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' \
    | LC_ALL=C tr -cd "$RUN_SCOPE_INSTANCE_ALPHABET"
}

# Prints the identifier this run's instance and project are both derived
# from: the artifact directory's basename, which every caller already
# makes unique per run, followed by this process's pid.
#
# The pid is not decoration.  Two runs started from two worktrees in the
# same second can carry the same artifact basename — `run-extended-
# suite.sh` gives its lifecycle case the fixed basename `infra-lifecycle`
# — and the pid is what separates them.  It is also what the liveness
# marker records, so the name and the marker agree on which run is which.
run_scope_token() {
  local artifact_dir="$1"
  printf '%s-%s' "$(basename "$artifact_dir")" "$$"
}

# Prints the instance name a run installs at: `prefix` followed by as
# much of the sanitised token as the length limit leaves room for.
#
# The *tail* of the token is what survives truncation, deliberately: the
# pid sits at the end, so two runs whose identifiers agree on everything
# else still derive different names.  Truncating the front instead would
# keep the part they share and drop the part they do not.
run_scope_instance() {
  local prefix="$1" token budget
  token="$(run_scope_sanitize "$2")"
  [ -n "$token" ] \
    || fail "the run identifier '$2' holds no [a-z0-9] character to derive an instance name from"
  budget=$((BOOTROOT_MAX_INSTANCE_NAME_LEN - ${#prefix}))
  [ "$budget" -ge 1 ] \
    || fail "the instance-name prefix '${prefix}' leaves no room for a run token within ${BOOTROOT_MAX_INSTANCE_NAME_LEN} characters"
  if [ "${#token}" -gt "$budget" ]; then
    token="${token:$((${#token} - budget))}"
  fi
  printf '%s%s\n' "$prefix" "$token"
}

# Aborts unless `name` is one `infra install` will accept.
#
# The derivation above is meant to produce nothing else, which is exactly
# why this is checked rather than trusted: a prefix edited later, or a
# limit that moves in `compose_project.rs`, would otherwise surface as a
# rejected install several minutes into a run.
run_scope_assert_valid_instance() {
  local name="$1"
  [ "${#name}" -le "$BOOTROOT_MAX_INSTANCE_NAME_LEN" ] \
    || fail "derived instance name '${name}' is ${#name} characters, over the ${BOOTROOT_MAX_INSTANCE_NAME_LEN}-character limit"
  case "$name" in
    ["$RUN_SCOPE_INSTANCE_ALPHABET"]*) ;;
    *) fail "derived instance name '${name}' does not start with a lowercase letter or a digit" ;;
  esac
  case "$name" in
    *[!"$RUN_SCOPE_INSTANCE_ALPHABET"-]*)
      fail "derived instance name '${name}' holds a character outside [a-z0-9-]"
      ;;
  esac
}

# Prints the Compose project a run's own `docker compose` calls must be
# scoped to, given the instance name it installs at.
#
# The same string, for the reason the header states: `--instance-name`
# makes the project the instance name, and a harness that used any other
# would be talking about a project its own install never created.  It is
# a function rather than an assignment so the reason lives in one place
# and both harnesses read it.
run_scope_project_for_instance() {
  printf '%s\n' "$1"
}

# Records the instance in a `.env` beside the directory a harness runs
# `bootroot` *from*, as opposed to the one its compose file sits in.
#
# `service add` takes no compose file at all: it resolves its identity
# with `ComposeIdentity::resolve_for_dir(Path::new("."), ...)`
# (`src/commands/service.rs`), from the same working directory it loads
# `state.json` from.  A harness that runs it from a workspace directory
# — which both lifecycle harnesses do, to keep `state.json` out of the
# source tree — would otherwise resolve the default identity there and
# look for `bootroot-http01` on project `bootroot`, find no responder of
# this run's, and skip the DNS-alias rewiring with a warning rather than
# a failure.  Recording the instance here is what keeps that path
# pointed at this run's own responder.
write_instance_dotenv() {
  local dir="$1" instance="$2" tmp
  tmp="$dir/.env.$$.tmp"
  printf 'BOOTROOT_INSTANCE=%s\n' "$instance" >"$tmp" \
    || fail "cannot record the instance name in ${dir}/.env"
  mv "$tmp" "$dir/.env" || fail "cannot publish ${dir}/.env"
}

# ---------------------------------------------------------------------------
# Liveness markers
# ---------------------------------------------------------------------------
#
# Giving every run its own project and instance stops a dead run's
# leftovers from being collected by accident.  Today the next run
# collects them, because it uses the same project and the same names and
# tears them down before starting; once nothing is ever named the same as
# a dead run's containers again, they accumulate for as long as the
# machine runs.  The start-of-run check in `lib/leftovers.sh` does not
# catch them and is not meant to: it matches the exact container names at
# *this* run's identity.
#
# A sweep has to tell a dead run's containers from a live one's, and with
# concurrent runs it cannot do that by name or by age — another run may
# legitimately own containers in the derived namespace right now.  So
# liveness is recorded rather than guessed: each run writes a marker
# naming its own pid and project, the sweep skips the markers whose pid
# is still alive, and tears the rest down by the exact names and the
# exact project label those markers record.  Never a prefix and never a
# wildcard: a `bootroot-*` sweep would reach into a real default-identity
# install on the same host.
#
# A recycled pid can spare a dead run's containers for one further run.
# That is acceptable — the next run collects them, and nothing is removed
# wrongly.

run_marker_path() {
  printf '%s/%s\n' "$BOOTROOT_E2E_RUN_MARKER_DIR" "$1"
}

# Prints the value one marker key holds, and nothing when the key is
# absent.
run_marker_field() {
  local file="$1" key="$2"
  awk -F= -v k="$key" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

# True when a process with this pid exists.
#
# `kill -0` reports a process owned by another user as an error, which is
# indistinguishable here from "no such process", so on Linux the process
# directory settles it.  Elsewhere — macOS, where there is no `/proc` —
# the marker directory is per-user, so another user's run has its own set
# of markers and never reaches this sweep at all.
run_pid_is_alive() {
  local pid="$1"
  case "$pid" in
    '' | *[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null && return 0
  [ -d "/proc/$pid" ]
}

# Creates the marker directory owner-only, and aborts unless it is this
# user's.
#
# A marker's filename is the instance the sweep tears down by exact
# container name, and its `project` field is the label the sweep removes
# volumes and networks by.  The directory therefore holds instructions,
# not just bookkeeping: anyone who can write to it can aim a
# `docker rm -f` at a name of their choosing — including `bootroot`, the
# one identity the sweep is meant never to reach.  Owner-only is what
# makes it per-user on Linux the way `$TMPDIR` already does on macOS.
#
# Ownership is asserted rather than inferred from the `chmod`.  `mkdir
# -p` succeeds on a directory that is already there whoever owns it, and
# re-moding one owned by someone else fails — so a `chmod` allowed to
# fail quietly would leave intact exactly the case it was added for: a
# directory another user pre-created world-writable at this predictable
# `/tmp` path.  Refusing it is the only answer available, since it is
# not this run's to re-mode.
#
# Both the sweep and the marker write go through here, because the sweep
# runs first and is the half that acts on what the directory says.
ensure_run_marker_dir() {
  mkdir -p "$BOOTROOT_E2E_RUN_MARKER_DIR" \
    || fail "cannot create the E2E run-marker directory ${BOOTROOT_E2E_RUN_MARKER_DIR}"
  [ -O "$BOOTROOT_E2E_RUN_MARKER_DIR" ] \
    || fail "the E2E run-marker directory ${BOOTROOT_E2E_RUN_MARKER_DIR} is not owned by this user; the sweep tears containers down by the names it holds, so a directory someone else can write is not one to read them from"
  chmod 700 "$BOOTROOT_E2E_RUN_MARKER_DIR" \
    || fail "cannot restrict the E2E run-marker directory ${BOOTROOT_E2E_RUN_MARKER_DIR} to its owner"
}

# Records this run as the live owner of `instance`.
#
# Published by rename, as every file another process may read is: a
# sweep reading a half-written marker would see no pid and collect a run
# that had only just started.
write_run_marker() {
  local instance="$1" project="$2" path tmp
  path="$(run_marker_path "$instance")"
  ensure_run_marker_dir
  tmp="${path}.$$.tmp"
  {
    printf 'pid=%s\n' "$$"
    printf 'project=%s\n' "$project"
  } >"$tmp" || fail "cannot write the E2E run marker ${tmp}"
  mv "$tmp" "$path" || fail "cannot publish the E2E run marker ${path}"
}

# Removes this run's own marker, and only this run's, once its teardown
# has left nothing behind.
#
# The recorded pid is compared rather than assumed: a marker naming
# another pid belongs to a run still using that instance, and removing it
# would hide that run's containers from every later sweep.
#
# The second argument is the teardown's status, and a non-zero one keeps
# the marker — the same rule `sweep_dead_run_instances` applies to a
# collection that did not finish, for the same reason.  A teardown that
# failed, or that left a container the end-of-run check reported, is the
# one case where this run's instance still holds resources after this
# run is gone.  Dropping the marker there would strand them under a name
# no later sweep knows to ask about, which is the accumulation the
# marker exists to stop; keeping it costs one retry by the next run,
# which finds this pid dead and collects what is left.
remove_run_marker() {
  local instance="${1:-}" teardown_status="${2:-0}" path recorded
  [ -n "$instance" ] || return 0
  path="$(run_marker_path "$instance")"
  [ -f "$path" ] || return 0
  recorded="$(run_marker_field "$path" pid)"
  [ "$recorded" = "$$" ] || return 0
  if [ "$teardown_status" -ne 0 ]; then
    echo "the teardown of ${instance} did not finish, so its run marker is kept for the next run to collect: ${path}" >&2
    return 0
  fi
  rm -f "$path"
}

# Tears one dead run's stack down, by the exact container names its
# instance produces and the exact `com.docker.compose.project` label its
# marker recorded.
#
# Containers are listed before they are removed, and listed again
# afterwards: two runs starting at the same moment sweep the same marker,
# so a `docker rm` that lost the race must not read as a failure, while a
# container that is genuinely still there must not read as success.
collect_dead_run_instance() {
  local instance="$1" project="$2" label="$3" log="$4" status=0
  local existing name ids id
  if ! existing="$(bootroot_leftover_containers "$instance")"; then
    echo "[${label}] cannot list this daemon's containers, so the leftovers of dead run ${instance} were not collected; see the docker error above" >&2
    return 1
  fi
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    docker rm -f "$name" >>"$log" 2>&1 || true
  done <<<"$existing"
  if ! existing="$(bootroot_leftover_containers "$instance")"; then
    echo "[${label}] cannot list this daemon's containers, so what the collection of dead run ${instance} removed is unknown; see the docker error above" >&2
    return 1
  fi
  existing="$(printf '%s\n' "$existing" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  if [ -n "$existing" ]; then
    echo "[${label}] could not remove the containers of dead run ${instance}: ${existing}" >&2
    status=1
  fi
  # Volumes and networks are reached by the project label the marker
  # recorded, which is as exact as the container names: a run's project
  # is its instance name, so a default-identity install's `bootroot`
  # project is out of reach here for the same reason its containers are.
  [ -n "$project" ] || return "$status"
  if ids="$(docker volume ls -q --filter "label=com.docker.compose.project=${project}" 2>>"$log")"; then
    for id in $ids; do
      docker volume rm -f "$id" >>"$log" 2>&1 || status=1
    done
  else
    echo "[${label}] cannot list the volumes of dead run ${instance}; see ${log}" >&2
    status=1
  fi
  if ids="$(docker network ls -q --filter "label=com.docker.compose.project=${project}" 2>>"$log")"; then
    for id in $ids; do
      docker network rm "$id" >>"$log" 2>&1 || status=1
    done
  else
    echo "[${label}] cannot list the networks of dead run ${instance}; see ${log}" >&2
    status=1
  fi
  return "$status"
}

# Collects every dead run's leftovers, and returns non-zero when any of
# it could not be collected.
#
# Deliberately not fatal to the caller.  This run's instance, containers
# and ports are its own, so another run's garbage cannot collide with
# them and aborting here would fail a run over someone else's mess.  What
# it must not do is stay quiet: every failure names the instance it could
# not clear, and the caller reports the non-zero status.
sweep_dead_run_instances() {
  local label="$1" log="$2" marker instance pid project status=0
  [ -d "$BOOTROOT_E2E_RUN_MARKER_DIR" ] || return 0
  # Aborts on a directory this user does not own, rather than reporting:
  # every name below is read out of it and handed to `docker rm -f`, so
  # one someone else can write is not a degraded input but a hostile one.
  ensure_run_marker_dir
  for marker in "$BOOTROOT_E2E_RUN_MARKER_DIR"/*; do
    [ -f "$marker" ] || continue
    case "$marker" in
      *.tmp) continue ;;
    esac
    instance="$(basename "$marker")"
    pid="$(run_marker_field "$marker" pid)"
    project="$(run_marker_field "$marker" project)"
    if run_pid_is_alive "$pid"; then
      continue
    fi
    printf '[%s] collecting the leftovers of dead run %s (pid %s, project %s)\n' \
      "$label" "$instance" "${pid:-unknown}" "${project:-unknown}" >>"$log"
    # The marker outlives a collection that did not finish, so the next
    # run retries it.  Dropping it there would strand whatever was left
    # behind under a name no later sweep knows to ask about — the very
    # accumulation this exists to stop.
    if collect_dead_run_instance "$instance" "$project" "$label" "$log"; then
      rm -f "$marker"
    else
      status=1
    fi
  done
  return "$status"
}
