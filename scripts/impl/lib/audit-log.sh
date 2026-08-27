# shellcheck shell=bash
# Shared assertions for the OpenBao file-audit backend.
#
# Sourced by lifecycle harnesses to verify, against the real OpenBao
# container, that the declarative `audit { type = "file" ... }` stanza
# in `openbao/openbao.hcl` actually produces an audit log at runtime
# and that the log captures representative AppRole login + KV read
# events. Callers must define a `fail` function that aborts the
# harness with a message; this helper invokes it on any failed check.

OPENBAO_AUDIT_CONTAINER_DEFAULT="bootroot-openbao"
OPENBAO_AUDIT_LOG_PATH_DEFAULT="/openbao/audit/audit.log"

# Asserts that the OpenBao file-audit backend wrote a non-empty
# audit log containing at least one `"type":"response"` entry for
# `auth/approle/login` and one for a `secret/data/...` KV read.
#
# The KV check requires `"operation":"read"` in addition to a
# `secret/data/...` path so that KV *writes* emitted by the harness
# (e.g. seeding runtime secrets) cannot alone satisfy the assertion.
assert_openbao_audit_log() {
  local container="${1:-$OPENBAO_AUDIT_CONTAINER_DEFAULT}"
  local path="${2:-$OPENBAO_AUDIT_LOG_PATH_DEFAULT}"

  if ! docker exec "$container" test -s "$path"; then
    fail "openbao audit log missing or empty: ${container}:${path}"
  fi

  if ! docker exec "$container" sh -c \
      "grep -F '\"type\":\"response\"' '$path' | grep -F '\"path\":\"auth/approle/login\"' >/dev/null"; then
    fail "openbao audit log missing AppRole login response entry: ${container}:${path}"
  fi

  if ! docker exec "$container" sh -c \
      "grep -F '\"type\":\"response\"' '$path' | grep -F '\"operation\":\"read\"' | grep -E '\"path\":\"secret/data/' >/dev/null"; then
    fail "openbao audit log missing KV read response entry (operation=read on secret/data/...): ${container}:${path}"
  fi
}

# ---------------------------------------------------------------------
# The reopen-on-signal probe
# ---------------------------------------------------------------------
#
# `bootroot-agent` rotates this device by renaming the active log aside
# and sending `SIGHUP` to the container's main process, so that OpenBao
# creates a fresh `audit.log` and not one byte is copied or truncated.
# That mechanism is a claim about the *image*: the compose entrypoint is
# a `sh -c` chain that ends in `exec docker-entrypoint.sh server ...`,
# and a wrapper anywhere along it that does not `exec` swallows the
# signal.
#
# So the claim is established here, against whatever image is actually
# running, on every lifecycle pass — rather than once, in a document
# that goes stale at the next image bump while every rotation silently
# degrades to the lossy copy-and-truncate fallback. The wiring is the
# point: a bump that breaks the reopen fails the build.
#
# The evidence is positive and file-level, never a zero exit status, and
# both halves are pinned to the same driven request: the new active log
# receives it and the renamed generation does not, with the generation's
# size captured only *after* the reopen is established so that writes
# buffered before it are not read as writes after it.

# How long the probe waits for the configured path to reappear.
#
# Generous, because a loaded CI runner is slower than a deployment. A
# budget that expires with no file there is a **refuted** reopen,
# reported as such — never inconclusive, and never lengthened to make a
# slow image pass.
#
# Fixed, and deliberately not read from the environment: an overridable
# budget is exactly the "longer wait bolted on" the paragraph above
# refuses, and a run that quietly extended it would report an
# established reopen the pinned budget refutes.
OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS=30

# How often it looks, inside that budget. Fixed for the same reason.
OPENBAO_AUDIT_REOPEN_POLL_SECONDS=0.5

# How long any one command the probe waits on may run.
#
# The budget above is a claim about the image; this one is about the
# harness surviving the machinery underneath it. A `docker exec` that
# never answers would otherwise park a lifecycle run for as long as the
# runner lives, with no result either way.
OPENBAO_AUDIT_PROBE_STEP_SECONDS=30

# How long a command that has been told to stop is given to do so before
# it is killed outright.
#
# A bound that only asks is not a bound. `docker` installs a `TERM`
# handler of its own and a container runtime under load can sit in it,
# and a shell wrapper anywhere in the way may ignore the signal
# entirely; either way the wait the bound exists to end simply
# continues. So the ask is followed by `KILL`, which nothing can
# decline.
OPENBAO_AUDIT_PROBE_KILL_GRACE_SECONDS=5

# Reports the probe's clock, in whole seconds.
#
# Whole seconds is the resolution `date` offers everywhere this runs, so
# each deadline below is enforced to within a second of the budget it
# names — under it rather than over, since the deadline is tested before
# the command that could satisfy it is issued.
openbao_audit_now() {
  date -u +%s
}

# Runs a command, abandoning it after `limit` seconds. Reports 124 when
# it does, the same convention `timeout` uses.
#
# Every wait in this probe is measured as elapsed time rather than as
# counted sleeps, because the two differ by however long Docker takes to
# answer: a loop that only counts its own sleeps runs for its budget
# *plus* every command in between, and then reports a reopen that the
# budget it names had already refuted. Bounding each command is the
# other half of the same point — an unbounded one both hangs the run and
# lands its answer after the budget closed.
#
# `timeout` would say this in one word and is not assumed: a stock macOS
# has none, and these harnesses run there.
#
# The timeout is recorded where the command cannot reach it, and the
# command is stopped in a way it cannot decline:
#
#   * The 124 comes from a marker the watchdog writes, never from the
#     child's exit status. A command is free to trap `TERM`, tidy up and
#     exit 0, and reading the status alone would take that for a
#     successful answer arriving inside the budget — the exact false
#     establishment this bound exists to prevent, one layer down.
#   * The child is started under job control so that it leads a process
#     group of its own, and the whole group is signalled. `docker exec`
#     is not a leaf: killing the client alone leaves whatever it spawned
#     behind, still holding the pipe this function's caller is reading.
#   * `TERM` first, then `KILL` after the grace above, so a command that
#     ignores the ask still stops and `wait` still returns.
openbao_audit_bounded() {
  local limit="$1"
  shift
  local pid watchdog deadline status marker monitor
  marker="$(mktemp "${TMPDIR:-/tmp}/bootroot-openbao-audit-bounded.XXXXXX")" || return 1
  deadline=$(($(openbao_audit_now) + limit))
  # `set -m` is what puts the child in its own process group, and it is
  # restored rather than assumed off: this file is sourced, and the
  # harness sourcing it may be running under job control already.
  monitor=""
  case "$-" in
    *m*) monitor="on" ;;
  esac
  set -m
  "$@" &
  pid=$!
  [ -n "$monitor" ] || set +m
  # The watchdog is redirected away from this function's own stdout, so
  # that it cannot hold a command substitution's pipe open after the
  # command it guards has been reaped, and it waits in one-second steps,
  # so that the `sleep` left behind when it is dismissed early outlives
  # it by no more than one of them. It stands down the moment the child
  # is gone, so a pid the parent has already reaped is never signalled.
  (
    hard_deadline=0
    while [ "$(openbao_audit_now)" -lt "$deadline" ]; do
      kill -0 "$pid" 2>/dev/null || exit 0
      sleep 1
    done
    kill -0 "$pid" 2>/dev/null || exit 0
    printf 'timeout\n' >"$marker"
    kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    hard_deadline=$(($(openbao_audit_now) + OPENBAO_AUDIT_PROBE_KILL_GRACE_SECONDS))
    while [ "$(openbao_audit_now)" -lt "$hard_deadline" ]; do
      kill -0 "$pid" 2>/dev/null || exit 0
      sleep 1
    done
    kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  ) >/dev/null 2>&1 &
  watchdog=$!
  status=0
  # The `wait` is what reports a job's death by signal, and that report
  # is the shell's, not the command's; it is silenced here so that a
  # bounded command cannot write a line into output a caller is
  # matching on. The command's own stderr is untouched — it was
  # inherited when the job was started.
  { wait "$pid" || status=$?; } 2>/dev/null
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  if [ -s "$marker" ]; then
    rm -f "$marker"
    return 124
  fi
  rm -f "$marker"
  if [ "$status" -gt 128 ]; then
    return 124
  fi
  return "$status"
}

# Runs one probe command under the step bound above.
openbao_audit_step() {
  openbao_audit_bounded "$OPENBAO_AUDIT_PROBE_STEP_SECONDS" "$@"
}

# Reports what `docker inspect` says about a container's process, which
# is how "no restart" is measured rather than observed.
openbao_audit_container_state() {
  openbao_audit_step docker inspect \
    -f '{{.State.StartedAt}} {{.RestartCount}} {{.State.Pid}}' "$1"
}

# Reports the seal state as `sealed=<bool> initialized=<bool>`.
openbao_audit_seal_state() {
  local url="${1%/}"
  curl -sS --max-time "$OPENBAO_AUDIT_PROBE_STEP_SECONDS" "${url}/v1/sys/seal-status" |
    jq -r '"sealed=\(.sealed) initialized=\(.initialized)"'
}

# Prints a curl config carrying one header, for curl to read on stdin.
#
# `--header` has no `@file` form, so a config is the only way to hand
# curl a header without putting it in `argv`. The value is escaped for
# curl's config parser, which reads `\\` and `\"` inside a quoted value
# and would otherwise end the value at the first quote in a token.
openbao_audit_curl_header_config() {
  printf 'header = "'
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
  printf '"\n'
}

# Prints an unused generation name under the current second's stamp.
#
# The daemon's own rotation publishes into this directory under exactly
# this naming, so the name derived from the current second can already
# be taken. The sequence is walked until one is free rather than
# assuming `-000000` is.
openbao_audit_free_generation() {
  local container="$1" dir="$2" stamp sequence candidate
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  sequence=0
  while [ "$sequence" -lt 1000 ]; do
    candidate="$(printf '%s/audit-%s-%06d.log' "$dir" "$stamp" "$sequence")"
    if ! openbao_audit_step docker exec "$container" test -e "$candidate" 2>/dev/null; then
      printf '%s\n' "$candidate"
      return 0
    fi
    sequence=$((sequence + 1))
  done
  return 1
}

# Runs the reopen protocol and answers 0 when it holds.
#
# Usage:
#   openbao_audit_reopen_probe <container> <openbao-url> <role-id> <secret-id> [log-path]
#
# Prints the reason on stderr and returns non-zero when it does not.
# Restores the renamed generation whenever it stops with the configured
# path absent, so a refuted probe does not leave the deployment without
# an audit log.
openbao_audit_reopen_probe() {
  local container="$1" url="${2%/}" role_id="$3" secret_id="$4"
  local path="${5:-$OPENBAO_AUDIT_LOG_PATH_DEFAULT}"
  local dir generation old_id new_id moved_id
  local state_before state_after seal_before seal_after
  local gen_size gen_size_after nonce token status attempt moved
  local deadline now reappeared arrived

  dir="$(dirname "$path")"

  # "No container restart" is measured, not observed: the three fields
  # and the seal state are captured before and compared after.
  state_before="$(openbao_audit_container_state "$container")" || {
    echo "probe: could not inspect ${container}" >&2
    return 1
  }
  seal_before="$(openbao_audit_seal_state "$url")" || true
  if [ "$seal_before" != "sealed=false initialized=true" ]; then
    echo "probe: OpenBao is not unsealed before the probe: ${seal_before}" >&2
    return 1
  fi

  # 1. Capture the active log's identity, and rename it aside.
  if ! old_id="$(openbao_audit_step docker exec "$container" stat -c '%d:%i' "$path")"; then
    echo "probe: no active audit log at ${container}:${path}" >&2
    return 1
  fi
  # `mv -n`, never a plain `mv`: the name is derived from the current
  # second, so it can collide with a generation `bootroot-agent` itself
  # published in that second, and a plain `mv` would silently destroy
  # that generation's records.
  #
  # But `mv -n` exits 0 when it refuses, on GNU and BSD alike, so the
  # rename is verified rather than trusted: the generation has to come
  # out carrying the identity the active log went in with. Without that
  # check a collision leaves the active log where it was, the probe
  # signals an unrotated device and step 4 refutes it — a red build
  # reporting an image fault that never happened.
  #
  # A name taken between the free-sequence check and the rename is
  # retried under the next free one rather than refuted: a daemon
  # rotation landing in the same second is not evidence about the image.
  attempt=0
  moved=""
  while [ "$attempt" -lt 3 ]; do
    attempt=$((attempt + 1))
    if ! generation="$(openbao_audit_free_generation "$container" "$dir")"; then
      echo "probe: every generation sequence under this second's stamp is taken" >&2
      return 1
    fi
    # The exit status is not what decides. `mv -n` reports a refused
    # destination differently across implementations — GNU and BSD both
    # succeed doing it — and only the filesystem says whether the inode
    # moved.
    openbao_audit_step docker exec "$container" mv -n "$path" "$generation" \
      >/dev/null 2>&1 || true
    moved_id="$(openbao_audit_step docker exec "$container" \
      stat -c '%d:%i' "$generation" 2>/dev/null || true)"
    if [ "$moved_id" = "$old_id" ]; then
      moved="yes"
      break
    fi
    # It did not move. With the active log still on its old inode the
    # destination was simply taken, so the next free sequence is tried;
    # anything else is not a collision and is not retried.
    if [ "$(openbao_audit_step docker exec "$container" \
      stat -c '%d:%i' "$path" 2>/dev/null || true)" != "$old_id" ]; then
      break
    fi
  done
  if [ -z "$moved" ]; then
    # Nothing is restored here: this probe moved nothing, so it has
    # nothing of its own to move back, and the generation name leads to
    # a file it did not put there.
    echo "probe: ${path} was never renamed aside; ${generation} carries '${moved_id}' rather \
than ${old_id}" >&2
    return 1
  fi

  # 2. Send the signal. `docker kill --signal=HUP` signals a running
  #    container; it is not a restart, which the state comparison pins.
  if ! openbao_audit_step docker kill --signal=HUP "$container" >/dev/null; then
    echo "probe: could not signal ${container}" >&2
    openbao_audit_restore_generation "$container" "$path" "$generation"
    return 1
  fi

  # 3. Poll for the configured path to reappear, until a deadline the
  #    budget fixes in elapsed time. The look itself is bounded by what
  #    is left of that budget, so no answer arrives after it: a file
  #    that comes back late is a refuted reopen, not a slow one.
  deadline=$(($(openbao_audit_now) + OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS))
  reappeared=""
  while :; do
    now="$(openbao_audit_now)"
    [ "$now" -lt "$deadline" ] || break
    if openbao_audit_bounded "$((deadline - now))" \
        docker exec "$container" test -e "$path" >/dev/null 2>&1; then
      reappeared="yes"
      break
    fi
    sleep "$OPENBAO_AUDIT_REOPEN_POLL_SECONDS"
  done
  if [ -z "$reappeared" ]; then
    echo "probe: REFUTED — ${path} did not reappear within \
${OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS}s of SIGHUP; this image does not reopen its file audit \
device on the signal" >&2
    openbao_audit_restore_generation "$container" "$path" "$generation"
    return 1
  fi

  # 4. A *new inode* at the path, not the same file back under its old
  #    name. Presence alone is not the test.
  new_id="$(openbao_audit_step docker exec "$container" stat -c '%d:%i' "$path")" || {
    echo "probe: could not stat the reopened ${path}" >&2
    return 1
  }
  if [ "$new_id" = "$old_id" ]; then
    echo "probe: REFUTED — ${path} carries the renamed generation's own identity (${old_id})" >&2
    return 1
  fi

  # 5. Only now capture the generation's size, so writes OpenBao
  #    buffered *before* the reopen are not read as writes after it.
  gen_size="$(openbao_audit_step docker exec "$container" \
    stat -c '%s' "$generation")" || return 1

  # 6. Drive one authenticated, non-mutating request whose audited path
  #    is unique to this run. A 403 or 404 is fine: the audit entry is
  #    what is asserted, and OpenBao writes the path into it in the
  #    clear.
  nonce="$(od -An -N8 -tx1 </dev/urandom | tr -d ' \n')"
  # The `secret_id` and the token it mints go to curl over a pipe, never
  # in `argv`. An argument is world-readable in `/proc` and in `ps` for
  # as long as the process runs, and these harnesses run on shared CI
  # runners and on developer machines with other people's agents on
  # them; the login body goes in through `--data @-` and the bearer
  # header through a config on stdin, which is the only way curl accepts
  # a header without spelling it on the command line.
  token="$(
    printf '{"role_id":"%s","secret_id":"%s"}' "$role_id" "$secret_id" |
      curl -sS --max-time "$OPENBAO_AUDIT_PROBE_STEP_SECONDS" \
        -X POST -H 'Content-Type: application/json' \
        --data @- "${url}/v1/auth/approle/login" | jq -r '.auth.client_token // empty'
  )"
  if [ -z "$token" ]; then
    echo "probe: the AppRole login returned no token" >&2
    return 1
  fi
  status="$(
    openbao_audit_curl_header_config "X-Vault-Token: ${token}" |
      curl -sS --max-time "$OPENBAO_AUDIT_PROBE_STEP_SECONDS" \
        -o /dev/null -w '%{http_code}' --config - \
        "${url}/v1/secret/data/bootroot-audit-reopen-probe/${nonce}"
  )"
  case "$status" in
    200 | 403 | 404) ;;
    *)
      echo "probe: the driven request answered ${status}" >&2
      return 1
      ;;
  esac

  # 7. Poll, against a deadline of its own, until the entry is in the
  #    new log.
  deadline=$(($(openbao_audit_now) + OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS))
  arrived=""
  while :; do
    now="$(openbao_audit_now)"
    [ "$now" -lt "$deadline" ] || break
    if openbao_audit_bounded "$((deadline - now))" \
        docker exec "$container" grep -qF "$nonce" "$path" >/dev/null 2>&1; then
      arrived="yes"
      break
    fi
    sleep "$OPENBAO_AUDIT_REOPEN_POLL_SECONDS"
  done
  if [ -z "$arrived" ]; then
    echo "probe: REFUTED — the driven request's entry never reached ${path} within \
${OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS}s" >&2
    return 1
  fi

  # 8. And the renamed generation received nothing further — both
  #    halves pinned to the same request.
  if openbao_audit_step docker exec "$container" grep -qF "$nonce" "$generation"; then
    echo "probe: REFUTED — the renamed generation also received the driven request" >&2
    return 1
  fi
  gen_size_after="$(openbao_audit_step docker exec "$container" \
    stat -c '%s' "$generation")" || return 1
  if [ "$gen_size_after" != "$gen_size" ]; then
    echo "probe: REFUTED — the renamed generation grew from ${gen_size} to ${gen_size_after} \
after the reopen" >&2
    return 1
  fi

  # And nothing was restarted or resealed to achieve any of it.
  state_after="$(openbao_audit_container_state "$container")" || return 1
  if [ "$state_after" != "$state_before" ]; then
    echo "probe: the container was restarted: '${state_before}' became '${state_after}'" >&2
    return 1
  fi
  seal_after="$(openbao_audit_seal_state "$url")" || true
  if [ "$seal_after" != "sealed=false initialized=true" ]; then
    echo "probe: OpenBao is not unsealed after the probe: ${seal_after}" >&2
    return 1
  fi

  printf 'openbao audit reopen established: %s -> %s, generation %s stayed at %s bytes\n' \
    "$old_id" "$new_id" "$generation" "$gen_size"
}

# Renames a generation back to the configured path when the probe
# stopped with that path absent.
#
# `mv -n` refuses to replace a file OpenBao has meanwhile created, which
# is the one thing this must never do.
openbao_audit_restore_generation() {
  local container="$1" path="$2" generation="$3"
  if openbao_audit_step docker exec "$container" test -e "$path" 2>/dev/null; then
    return 0
  fi
  openbao_audit_step docker exec "$container" mv -n "$generation" "$path" \
    >/dev/null 2>&1 || true
}

# Asserts the reopen holds, failing the harness when it does not.
assert_openbao_audit_reopen() {
  openbao_audit_reopen_probe "$@" ||
    fail "openbao audit device does not reopen on SIGHUP; bootroot-agent's rotation would \
silently degrade to the lossy copy-and-truncate fallback on this image"
}

# How long after the signal the late-reopen stand-in recreates the log.
#
# Past the budget, so the probe must refute it, and not far past: what
# it guards against is a probe that measures its budget in counted
# sleeps rather than in elapsed time, and such a probe keeps waiting for
# the budget *plus* every `docker exec` in between — comfortably long
# enough to see a file that arrives here and call the reopen
# established.
OPENBAO_AUDIT_LATE_REOPEN_DELAY_SECONDS=40

# Runs the probe against a stand-in of the reference container's own
# image, whose main process is the given `sh -c` script.
#
# The stand-in carries the reference container's own Compose project
# label. It is removed on the line after the probe returns, but a run
# killed in between would otherwise strand it for as long as the machine
# runs: the E2E teardown and the dead-run sweep both collect by
# `com.docker.compose.project`, and the startup leftover check matches
# only the fixed service-name suffixes, so an unlabelled container of
# this name is reachable by none of the three.
#
# The probe's status and combined output are left in
# `OPENBAO_AUDIT_STANDIN_STATUS` and `OPENBAO_AUDIT_STANDIN_OUTPUT`,
# since a function can return only one of the two.
openbao_audit_run_against_standin() {
  local reference="$1" url="$2" suffix="$3" script="$4"
  local image project standin
  local -a labels=()

  image="$(docker inspect -f '{{.Config.Image}}' "$reference")" ||
    fail "could not read the image of ${reference}"
  project="$(docker inspect \
    -f '{{index .Config.Labels "com.docker.compose.project"}}' "$reference")" ||
    fail "could not read the Compose project of ${reference}"
  [ -z "$project" ] || labels=(--label "com.docker.compose.project=${project}")
  standin="${reference}-${suffix}"
  docker rm -f "$standin" >/dev/null 2>&1 || true
  # `${labels[@]+…}`, not a bare `${labels[@]}`: under `set -u` an empty
  # array is an unbound variable before bash 4.4, and this file is
  # sourced by harnesses that set it.
  docker run -d --name "$standin" ${labels[@]+"${labels[@]}"} --entrypoint sh "$image" -c \
    "$script" >/dev/null || fail "could not start the ${suffix} stand-in"

  OPENBAO_AUDIT_STANDIN_STATUS=0
  # The run stops at the reappearance budget, before it reaches the
  # credentials, so those are placeholders.
  OPENBAO_AUDIT_STANDIN_OUTPUT="$(
    openbao_audit_reopen_probe "$standin" "$url" "role" "secret" 2>&1
  )" || OPENBAO_AUDIT_STANDIN_STATUS=$?
  docker rm -f "$standin" >/dev/null 2>&1 || true
}

# Asserts the probe itself is capable of refusing.
#
# A green check proves nothing until it has been shown to go red, and
# this one gates whether a whole mechanism is honest about the image it
# runs on. The stand-in is a container of the *same image* whose main
# process ignores `SIGHUP`, so what is simulated is precisely a chain
# that swallows the signal — not a different image, a different path or
# a shorter wait. It is given the real deployment's URL so that every
# precondition passes and the run reaches the reappearance budget: the
# refusal has to come from the reopen evidence, not from a container the
# probe could not talk to.
#
# Usage:
#   assert_openbao_audit_reopen_probe_refutes_a_non_reopening_target <reference-container> <url>
assert_openbao_audit_reopen_probe_refutes_a_non_reopening_target() {
  openbao_audit_run_against_standin "$1" "$2" "reopen-probe-standin" \
    'trap "" HUP; mkdir -p /openbao/audit; : > /openbao/audit/audit.log; while true; do sleep 1; done'
  if [ "$OPENBAO_AUDIT_STANDIN_STATUS" -eq 0 ]; then
    fail "the openbao audit reopen probe passed a target that does not reopen; the check that \
guards the rotation mechanism cannot itself be trusted"
  fi
  case "$OPENBAO_AUDIT_STANDIN_OUTPUT" in
    *"did not reappear within"*) ;;
    *)
      fail "the openbao audit reopen probe refused the non-reopening stand-in for the wrong \
reason, so it is not the reopen evidence that would go red: \
${OPENBAO_AUDIT_STANDIN_OUTPUT}"
      ;;
  esac
}

# Asserts the probe refuses a reopen that arrives after its budget.
#
# The budget is a claim about elapsed time, and the difference between
# holding to it and drifting past it is invisible in a green run: a
# stand-in that never reopens is refused either way. So this one *does*
# reopen — it honours `SIGHUP` and recreates the log, but only once the
# budget has passed. An image that needs longer than the pinned budget
# is an image the rotation degrades on, so the answer has to be the same
# refusal, and a probe that waited long enough to see this file would be
# reporting an established reopen the budget it names refutes.
#
# Usage:
#   assert_openbao_audit_reopen_probe_refutes_a_late_reopen <reference-container> <url>
assert_openbao_audit_reopen_probe_refutes_a_late_reopen() {
  openbao_audit_run_against_standin "$1" "$2" "late-reopen-probe-standin" \
    "mkdir -p /openbao/audit; : > /openbao/audit/audit.log; \
trap 'sleep ${OPENBAO_AUDIT_LATE_REOPEN_DELAY_SECONDS}; : > /openbao/audit/audit.log' HUP; \
while true; do sleep 1; done"
  if [ "$OPENBAO_AUDIT_STANDIN_STATUS" -eq 0 ]; then
    fail "the openbao audit reopen probe established a reopen that arrived \
${OPENBAO_AUDIT_LATE_REOPEN_DELAY_SECONDS}s after the signal, past its \
${OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS}s budget; the budget is not being measured in elapsed time"
  fi
  case "$OPENBAO_AUDIT_STANDIN_OUTPUT" in
    *"did not reappear within"*) ;;
    *)
      fail "the openbao audit reopen probe refused the late-reopening stand-in for the wrong \
reason, so it is not the budget that would go red: ${OPENBAO_AUDIT_STANDIN_OUTPUT}"
      ;;
  esac
}

# How long the bound self-test gives each of its two stand-in commands.
#
# One second, because what is under test is that the bound fires and
# that what it fires stops the command — neither of which depends on how
# long it waited first. The probe's own 30-second step bound would only
# add a minute to every lifecycle run to prove the same thing.
OPENBAO_AUDIT_BOUND_SELFTEST_LIMIT_SECONDS=1

# Asserts the probe's command bound stops a command that will not stop
# itself.
#
# Every wait in the probe runs under that bound, so a bound that can be
# declined is a probe that can hang — and, worse, one that reports the
# command's own answer for a wait whose budget had already closed. Green
# runs say nothing about either: a command that answers in time is
# bounded correctly whatever the bound does when it fires.
#
# Two stand-ins, one per way a bound can be talked out of it. The first
# traps the signal, takes longer than the budget and exits 0, so a bound
# that reads the child's exit status reports a success the budget
# refused. The second ignores the signal outright and leaves a child of
# its own behind, so an ask with nothing behind it never returns at all.
assert_openbao_audit_bound_stops_a_command_that_will_not_stop() {
  local status started elapsed ceiling pidfile leader follower waited

  status=0
  openbao_audit_bounded "$OPENBAO_AUDIT_BOUND_SELFTEST_LIMIT_SECONDS" \
    sh -c 'trap "sleep 2; exit 0" TERM; sleep 300 & wait' >/dev/null 2>&1 || status=$?
  if [ "$status" -ne 124 ]; then
    fail "the openbao audit probe's command bound answered ${status} rather than 124 for a \
command that trapped its signal and exited 0 past the budget; a timed-out command's own exit \
status is being read as the probe's answer, so a late reopen can still be reported as \
established"
  fi

  pidfile="$(mktemp "${TMPDIR:-/tmp}/bootroot-openbao-audit-bound-selftest.XXXXXX")" ||
    fail "could not create the openbao audit bound self-test's pid file"
  status=0
  started="$(openbao_audit_now)"
  # The stand-in's `$$` and `$!` are the *stand-in's*, so the quotes are
  # single deliberately; the pid file reaches it as `$1` rather than
  # through an expansion for the same reason.
  # shellcheck disable=SC2016
  openbao_audit_bounded "$OPENBAO_AUDIT_BOUND_SELFTEST_LIMIT_SECONDS" \
    sh -c 'trap "" TERM; sleep 300 & printf "%s %s\n" "$$" "$!" >"$1"; while true; do
      sleep 1
    done' sh "$pidfile" >/dev/null 2>&1 || status=$?
  elapsed=$(($(openbao_audit_now) - started))
  leader=""
  follower=""
  read -r leader follower <"$pidfile" || true
  rm -f "$pidfile"
  if [ "$status" -ne 124 ]; then
    fail "the openbao audit probe's command bound answered ${status} rather than 124 for a \
command that ignores its signal"
  fi
  ceiling=$((OPENBAO_AUDIT_BOUND_SELFTEST_LIMIT_SECONDS +
    OPENBAO_AUDIT_PROBE_KILL_GRACE_SECONDS + 5))
  if [ "$elapsed" -gt "$ceiling" ]; then
    fail "the openbao audit probe's command bound took ${elapsed}s to abandon a command that \
ignores its signal, past the ${ceiling}s its budget and kill grace allow"
  fi
  # Without both pids there is nothing to check for, and a check with
  # nothing to look for passes. That is a broken self-test, not a bound
  # that held.
  if [ -z "$leader" ] || [ -z "$follower" ]; then
    fail "the openbao audit bound self-test's stand-in recorded no process group \
('${leader}', '${follower}'), so nothing proves the bound killed one"
  fi
  # The command led a process group and left a child in it, so the
  # evidence is that *both* are gone: signalling the leader alone would
  # leave the child holding the pipe the probe reads. A moment is
  # allowed for the reparented child to be reaped after the kill.
  waited=0
  while [ "$waited" -lt 5 ]; do
    kill -0 "$leader" 2>/dev/null || kill -0 "$follower" 2>/dev/null || return 0
    sleep 1
    waited=$((waited + 1))
  done
  kill -KILL -"$leader" 2>/dev/null || true
  kill -KILL "$follower" 2>/dev/null || true
  fail "the openbao audit probe's command bound reported abandoning a command that ignores its \
signal while leaving its process group running (${leader}, ${follower}); a stuck docker \
invocation would still hold the probe's pipe open"
}
