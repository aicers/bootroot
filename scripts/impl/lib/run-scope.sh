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
# the liveness bookkeeping that unique naming makes necessary — and, at
# the end, the one lock that keeps `hosts` mode serialised, since
# `/etc/hosts` is the one thing left that no derivation can give a run
# its own copy of.
#
# The instance and the Compose project are derived separately, from the
# same run identifier, under different rules — and they have to be.  An
# instance name is a prefix on container names, which are DNS labels and
# certificate SANs, so it is validated and capped at 39 characters; a
# CI-length `GITHUB_RUN_ID` carries the identifier past that on its own.
# A Compose project carries no such limit, so it keeps the identifier
# whole and stays legible in `docker ps` when the truncated instance no
# longer is.
#
# Both then have to be made effective, by different routes.  The instance
# reaches `infra install` as `--instance-name`, which is what records it
# in `.env` and names every container the binary later creates — the
# `-openbao-agent-stepca` and `-openbao-agent-responder` sidecars
# included.  The project reaches it as an exported `COMPOSE_PROJECT_NAME`,
# which outranks the declared identity for the project and nothing else
# (`resolve_compose_project_for_dir`, `src/commands/compose_project.rs`),
# and which every later `bootroot` invocation in the run resolves the
# same way.  `assert_resolved_compose_project` in each harness then reads
# the project the install actually resolved back off a real container,
# because a run whose binary resolved some other project would tear down
# a project holding none of its containers.
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
#
# The uid is in the name so Linux gets that separation too, where
# `TMPDIR` is usually unset and `/tmp` is the whole machine's.  Without
# it two users cannot both run the harness on one host: the first
# creates the directory 0700, and `ensure_run_marker_dir` then refuses
# it for the second — which is the same serialisation this issue exists
# to remove, arriving as a hard failure instead of a collision.  The
# ownership check below stays regardless, because a predictable path is
# still one somebody else can get to first.
BOOTROOT_E2E_RUN_MARKER_DIR="${BOOTROOT_E2E_RUN_MARKER_DIR:-${TMPDIR:-/tmp}/bootroot-e2e-runs-$(id -u)}"

# The repository half of the responder image tag, as
# `docker-compose.yml` and `docker-compose.deploy.yml` both spell it.
# The tag half is this run's instance name, which is what keeps two
# concurrent runs off one image.
BOOTROOT_HTTP01_IMAGE_REPO="bootroot-http01-responder"

# The characters `validate_instance_name` accepts after the prefix,
# spelled out rather than written as `a-z0-9`.  A bracket range is
# collated by the caller's locale, and under most of them `[a-z]` matches
# `E` — which would let an uppercase name through the guard below and
# have `infra install` reject it several minutes into a run.
RUN_SCOPE_INSTANCE_ALPHABET="abcdefghijklmnopqrstuvwxyz0123456789"

# What a Compose project name may hold after its first character, per
# Compose's own rule.  Wider than the instance alphabet on purpose: the
# project is not truncated, so it can afford to keep the `-` separators
# that make the run identifier readable in `docker ps` and in a label
# filter.  Spelled out for the same collation reason as above.
RUN_SCOPE_PROJECT_ALPHABET="abcdefghijklmnopqrstuvwxyz0123456789-_"

# Reduces a free-form run identifier to the alphabet an instance name may
# use, dropping every other character rather than mapping it to `-`: the
# result is a token to be appended to a prefix, and a mapped separator
# would spend the length budget on punctuation.
run_scope_sanitize() {
  printf '%s' "$1" \
    | LC_ALL=C tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' \
    | LC_ALL=C tr -cd "$RUN_SCOPE_INSTANCE_ALPHABET"
}

# Reduces a free-form run identifier to what a Compose project name may
# hold, keeping the separators `run_scope_sanitize` drops.  Nothing here
# is truncated, so there is no length budget for a separator to spend.
run_scope_project_sanitize() {
  printf '%s' "$1" \
    | LC_ALL=C tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' \
    | LC_ALL=C tr -cd "$RUN_SCOPE_PROJECT_ALPHABET"
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

# Prints the Compose project a run scopes every `docker compose` call to
# — its own and the ones `bootroot` makes — derived from the same token
# as the instance name and under its own rule.
#
# Nothing is truncated here.  A Compose project has no DNS label to fit
# inside and no certificate SAN to appear in, so it keeps the whole run
# identifier: that is what makes it unique without relying on the pid
# alone, and what keeps a `com.docker.compose.project` filter legible
# after the instance name has been cut to 39 characters.  For a
# CI-length `GITHUB_RUN_ID` the two therefore differ in length as well as
# in content, which is the point of deriving them separately.
run_scope_project() {
  local prefix="$1" token
  token="$(run_scope_project_sanitize "$2")"
  [ -n "$token" ] \
    || fail "the run identifier '$2' holds no character a Compose project name may use"
  printf '%s%s\n' "$prefix" "$token"
}

# Aborts unless `name` is one Compose will accept as a project.
#
# Checked for the same reason the instance name is: a prefix edited later
# would otherwise surface as a rejected `docker compose` call several
# minutes into a run.  Compose requires a lowercase letter or a digit
# first, then lowercase letters, digits, `-` and `_`.
run_scope_assert_valid_project() {
  local name="$1"
  [ -n "$name" ] || fail "the derived Compose project name is empty"
  case "$name" in
    ["$RUN_SCOPE_INSTANCE_ALPHABET"]*) ;;
    *) fail "derived Compose project '${name}' does not start with a lowercase letter or a digit" ;;
  esac
  case "$name" in
    *[!"$RUN_SCOPE_PROJECT_ALPHABET"]*)
      fail "derived Compose project '${name}' holds a character outside [a-z0-9_-]"
      ;;
  esac
}

# Prints the responder image a run builds and runs its own stack from.
#
# The compose file declares one `build:` context, and its `image:` is the
# tag that build is written to.  Left at the shipped default, two
# concurrent runs write to the same tag in turn: the second run's
# `up --build` retags it while the first is up, and the first's later
# `up -d bootroot-http01` — the recreate that applies the DNS aliases —
# resolves the tag again and starts the other run's build.  A running
# container holds its image by id, so nothing is disturbed until that
# recreate, which is exactly the point at which it is.
#
# So the tag is the run's instance name.  Derived rather than recorded,
# for the same reason the nine container names are: it is a function of
# the instance, so a sweep reading a marker's filename can name it
# exactly.
run_scope_http01_image() {
  printf '%s:%s\n' "$BOOTROOT_HTTP01_IMAGE_REPO" "$1"
}

# Removes one run's responder image, and returns non-zero only when the
# tag is still there afterwards.
#
# An absent tag is not a failure: a run killed before its install built
# anything has none, and neither has one whose image a concurrent sweep
# already removed.  What must not pass is a tag that survived the
# removal — that is a run's leftovers under a name only this derivation
# knows, which is what the marker exists to keep collectable.
#
# What is removed is always a tag and never an image id, which is what
# makes this safe when a run's build came out byte-identical to another
# tag's: Docker untags a multiply-tagged image rather than deleting it,
# so the `:latest` a real install left on the same layers stays.
remove_run_image() {
  local image="$1" log="$2"
  docker image inspect "$image" >/dev/null 2>&1 || return 0
  docker image rm -f "$image" >>"$log" 2>&1 || true
  ! docker image inspect "$image" >/dev/null 2>&1
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
# indistinguishable here from "no such process", so two more probes stand
# behind it: the process directory on Linux, and `ps -p` where there is
# none.  Both see another user's process, which the `/etc/hosts` lock
# below needs — that lock is machine-wide, so the pid it records is
# regularly not this user's, and reading it as dead would hand two runs
# the file at once.  The marker sweep only gains by the same
# conservatism: a pid recycled by anyone's process spares a dead run's
# containers for one more round, which is the trade already recorded
# below, and never removes a live run's.
run_pid_is_alive() {
  local pid="$1"
  case "$pid" in
    '' | *[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null && return 0
  [ -d "/proc/$pid" ] && return 0
  ps -p "$pid" >/dev/null 2>&1
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
# A symbolic link is refused before that, because ownership cannot see
# one: every test operator but `-L` follows the link, so `-O` reports on
# the target.  Someone who plants a link at this path pointing at a
# directory *this* user owns therefore passes the ownership check, and
# aims the whole of the rest at a directory that was never the harness's
# — the `chmod` re-modes it to 0700, the sweep reads its filenames as
# instance names, and `rm -f "$marker"` deletes each file it finds once
# the containers those names would produce are gone.  `mkdir -p`
# succeeds on a link to a directory, so this has to be checked after it
# and before anything acts on the path.
#
# Both the sweep and the marker write go through here, because the sweep
# runs first and is the half that acts on what the directory says.
ensure_run_marker_dir() {
  mkdir -p "$BOOTROOT_E2E_RUN_MARKER_DIR" \
    || fail "cannot create the E2E run-marker directory ${BOOTROOT_E2E_RUN_MARKER_DIR}"
  [ ! -L "$BOOTROOT_E2E_RUN_MARKER_DIR" ] \
    || fail "the E2E run-marker directory ${BOOTROOT_E2E_RUN_MARKER_DIR} is a symbolic link; the sweep re-modes it, reads container names out of it and removes what it reads, so it must be the directory itself and not a pointer at somebody else's choosing"
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
  # The responder image that run built for itself, named by the same
  # derivation the containers were: a tag carrying an instance name no
  # other run derives, so the shipped `:latest` a real install produced
  # is as far out of reach here as its containers are.
  if ! remove_run_image "$(run_scope_http01_image "$instance")" "$log"; then
    echo "[${label}] could not remove the responder image of dead run ${instance}" >&2
    status=1
  fi
  # Volumes and networks are reached by the project label the marker
  # recorded, which is as exact as the container names: the label filter
  # matches that one project and no other, so a default-identity
  # install's `bootroot` project is out of reach here for the same
  # reason its containers are.  The project is read from the marker
  # rather than derived from the instance, because the two are separate
  # values and only the marker knows which project went with which
  # instance.
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

# ---------------------------------------------------------------------------
# The `/etc/hosts` mutex
# ---------------------------------------------------------------------------
#
# Everything above makes two `no-hosts` runs independent.  `hosts` mode
# is deliberately left out of that: the entries a run adds are keyed by a
# fixed host name (`stepca.internal`, `responder.internal`) and removed
# by a fixed marker literal, and rewriting `/etc/hosts` is an unlocked
# read-modify-write on one file the whole machine shares.  No spelling of
# the marker fixes either half.
#
# That mode used to be serialised by accident, and only by accident.  Two
# runs collided on the Compose project, on container names and on ports
# long before either reached `/etc/hosts`, so the second failed at `up`.
# Once every run has its own project, names and ports, nothing stops them
# from reaching that file together — and what happens then is silent
# rather than loud: the second run finds the host names already there and
# adds nothing, then the first run's cleanup strips both marker lines
# while the second is still resolving through them.
#
# So the serialisation is stated instead of inherited.  One run at a time
# holds this lock, and a second is refused before it touches the file.
#
# The path is machine-wide, unlike the per-user marker directory above,
# because `/etc/hosts` is: a per-user lock would leave two users' runs
# free to interleave on the one file both are editing.  `$TMPDIR` is per
# user on macOS, which is exactly what is not wanted here, so this is
# `/tmp` outright.
#
# A shared path at a predictable location is worth less caution here than
# it is for the marker directory, and the difference is what the file is
# used for.  Nothing is read out of this one and handed to `docker rm`:
# it holds a pid to test for liveness and a name to put in a message.  So
# a lock somebody else planted denies `hosts` runs — loudly, naming the
# path — where a marker directory somebody else planted would have aimed
# a teardown.
#
# What a machine-wide path in `/tmp` does cost is the recovery of a
# killed run's lock, and that has to be paid rather than accepted:
# `/tmp` is sticky, so the next user's run cannot unlink the file the
# killed user's run left behind, and `hosts` mode would stay refused for
# everyone but its owner.  `hosts_lock_clear_stale` below therefore falls
# back to the `sudo -n` the mode already requires.
BOOTROOT_E2E_HOSTS_LOCK="${BOOTROOT_E2E_HOSTS_LOCK:-/tmp/bootroot-e2e-hosts.lock}"

# Whether this process is the run holding the lock.  Consulted by
# `cleanup_hosts` in both harnesses, which must rewrite `/etc/hosts` only
# on behalf of a run that put entries there: a run refused at the lock,
# or one that failed before taking it, would otherwise remove the live
# holder's lines on its way out.
BOOTROOT_HOSTS_LOCK_HELD=0

# True when this process holds the `/etc/hosts` lock.
hosts_lock_held() {
  [ "$BOOTROOT_HOSTS_LOCK_HELD" -eq 1 ]
}

# Creates the lock file, and only when it is not already there.
#
# `noclobber` turns `>` into an exclusive create, which is the whole
# mechanism: two runs racing here — at the first attempt, or at the retry
# after one of them cleared a stale lock — cannot both succeed, where a
# test-then-write would let both through.
#
# World-readable on purpose, whatever the umask that created it.  The
# next run to arrive here is regularly another user's, and the pid this
# file holds is what tells it whether the run holding the lock is still
# alive.  A lock it cannot read is one it must refuse rather than clear —
# an unreadable pid is not a dead one — so a run started under `umask
# 077` would otherwise deny `hosts` mode to every other user on the
# machine for as long as it lasted, and past its death.  Nothing in here
# is a secret: a pid and a one-line description of the run.
hosts_lock_create() {
  local holder="$1"
  (
    set -o noclobber
    printf 'pid=%s\nholder=%s\n' "$$" "$holder" >"$BOOTROOT_E2E_HOSTS_LOCK"
  ) 2>/dev/null || return 1
  chmod 644 "$BOOTROOT_E2E_HOSTS_LOCK" 2>/dev/null || true
}

# Removes a lock whose recorded pid is dead, through the privileged path
# when this user's own unlink is refused.
#
# The refusal is the normal case across users rather than an unusual one.
# `/tmp` is sticky on every system this harness runs on, so only a file's
# owner may unlink it there, and the lock is deliberately machine-wide:
# the run that finds it stale is exactly the run that did not write it.
# A plain `rm` therefore recovers a killed run's lock only for the user
# who was killed, which leaves `hosts` mode refused on that host for
# everybody else until that user or root removes a file by hand — the
# per-user serialisation this issue exists to remove, arriving as a hard
# failure.
#
# `sudo -n` is already a precondition of the mode, checked by the caller
# before it gets here: a run that cannot edit `/etc/hosts` unprompted
# never reaches the lock at all.  So the privileged unlink asks for
# nothing the run does not already have.
#
# It is also a safe thing to hand root.  `rm` unlinks a symbolic link
# rather than following it, so the link the path is checked for above
# cannot aim this at a file of somebody else's choosing even if one is
# planted between the check and here, and a hard link planted at this
# path costs the file it points at one of its names and none of its
# contents.  What decides whether this runs at all is the pid read out of
# the lock, and that decision is made before anything is removed.
hosts_lock_clear_stale() {
  rm -f -- "$BOOTROOT_E2E_HOSTS_LOCK" 2>/dev/null && return 0
  # A holder that released it in between: gone is gone, whoever won.
  [ -e "$BOOTROOT_E2E_HOSTS_LOCK" ] || return 0
  # root's unlink has already been tried, and there is nothing above it.
  if [ "$(id -u)" -eq 0 ]; then
    return 1
  fi
  command -v sudo >/dev/null 2>&1 || return 1
  sudo -n rm -f -- "$BOOTROOT_E2E_HOSTS_LOCK" 2>/dev/null
}

# Takes the `/etc/hosts` lock for this run, or aborts.
#
# Refusal rather than waiting.  A `hosts` run holds the file for its
# whole length — the entries have to outlive every resolution the run
# makes — so a queue here is a wait of minutes with no bound worth
# writing down, and the caller is a harness whose operator can start it
# again.  What matters is that the second run stops before it edits the
# file, not that it eventually gets a turn.
#
# A lock naming a dead pid is cleared and retried once: a run killed with
# `SIGKILL` never reaches its own release, and leaving that lock in place
# would refuse `hosts` mode on this machine until somebody deleted a file
# by hand.  Its `/etc/hosts` entries survive that too, and are collected
# by the next run's own `add_hosts_entry`/`cleanup_hosts` pair, which
# match on the host name and the marker rather than on who wrote them.
# The clearing goes through `hosts_lock_clear_stale`, because the run
# that finds a lock stale is regularly not the user who wrote it and
# `/tmp` lets nobody but that user unlink it.
#
# A lock that exists and cannot be read is refused instead of cleared.
# Liveness is the only thing that licenses a removal here, and it is read
# out of the file: a pid that cannot be read is not a pid that is dead,
# and clearing on it would hand `/etc/hosts` to two runs at once.
acquire_hosts_lock() {
  local holder="$1" owner_pid owner_holder
  # Checked before anything acts on the path, and for the reason
  # `ensure_run_marker_dir` checks it: `-e` and the rest follow a link,
  # so a link planted here aims the create and the `rm` below at a file
  # of somebody else's choosing.
  [ ! -L "$BOOTROOT_E2E_HOSTS_LOCK" ] \
    || fail "the E2E hosts lock ${BOOTROOT_E2E_HOSTS_LOCK} is a symbolic link; it must be the file itself and not a pointer at somebody else's choosing"
  # Twice: the first attempt, and one more after a lock naming a dead
  # pid has been cleared.  No further, because a second failure means
  # another run took it in between, which is the answer rather than a
  # reason to keep trying.
  for _ in 1 2; do
    if hosts_lock_create "$holder"; then
      BOOTROOT_HOSTS_LOCK_HELD=1
      return 0
    fi
    if [ -e "$BOOTROOT_E2E_HOSTS_LOCK" ] && [ ! -r "$BOOTROOT_E2E_HOSTS_LOCK" ]; then
      fail "the E2E hosts lock ${BOOTROOT_E2E_HOSTS_LOCK} cannot be read, so whether the run holding it is still alive cannot be told; it is treated as held — wait for that run to finish, or use RESOLUTION_MODE=no-hosts, which has no such limit"
    fi
    owner_pid="$(run_marker_field "$BOOTROOT_E2E_HOSTS_LOCK" pid 2>/dev/null || true)"
    owner_holder="$(run_marker_field "$BOOTROOT_E2E_HOSTS_LOCK" holder 2>/dev/null || true)"
    if run_pid_is_alive "$owner_pid"; then
      fail "another E2E run is already resolving through /etc/hosts (pid ${owner_pid}, ${owner_holder:-unknown}); hosts mode edits one file the whole machine shares under a fixed marker, so it runs one at a time — wait for that run to finish, or use RESOLUTION_MODE=no-hosts, which has no such limit"
    fi
    hosts_lock_clear_stale \
      || fail "the E2E hosts lock ${BOOTROOT_E2E_HOSTS_LOCK} names the dead pid ${owner_pid:-unknown} and could not be removed, by this user or through sudo -n; remove it once you are certain no run is resolving through /etc/hosts"
  done
  fail "could not take the E2E hosts lock ${BOOTROOT_E2E_HOSTS_LOCK}; another run took it while this one was clearing a dead run's"
}

# Releases the lock, and only when this process is what it records.
#
# The recorded pid is compared for the reason `remove_run_marker`
# compares it: a lock naming another pid belongs to a run still editing
# the file, and removing it would let a third run in alongside that one.
release_hosts_lock() {
  local owner
  hosts_lock_held || return 0
  BOOTROOT_HOSTS_LOCK_HELD=0
  owner="$(run_marker_field "$BOOTROOT_E2E_HOSTS_LOCK" pid 2>/dev/null || true)"
  [ "$owner" = "$$" ] || return 0
  rm -f "$BOOTROOT_E2E_HOSTS_LOCK"
}
