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
OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS="${OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS:-30}"

# How often it looks, inside that budget.
OPENBAO_AUDIT_REOPEN_POLL_SECONDS="${OPENBAO_AUDIT_REOPEN_POLL_SECONDS:-0.5}"

# Reports what `docker inspect` says about a container's process, which
# is how "no restart" is measured rather than observed.
openbao_audit_container_state() {
  docker inspect -f '{{.State.StartedAt}} {{.RestartCount}} {{.State.Pid}}' "$1"
}

# Reports the seal state as `sealed=<bool> initialized=<bool>`.
openbao_audit_seal_state() {
  local url="${1%/}"
  curl -sS "${url}/v1/sys/seal-status" |
    jq -r '"sealed=\(.sealed) initialized=\(.initialized)"'
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
  local dir generation old_id new_id
  local state_before state_after seal_before seal_after
  local gen_size gen_size_after nonce token status waited

  dir="$(dirname "$path")"
  generation="${dir}/audit-$(date -u +%Y%m%dT%H%M%SZ)-000000.log"

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
  if ! old_id="$(docker exec "$container" stat -c '%d:%i' "$path")"; then
    echo "probe: no active audit log at ${container}:${path}" >&2
    return 1
  fi
  if ! docker exec "$container" mv "$path" "$generation"; then
    echo "probe: could not rename ${path} aside to ${generation}" >&2
    return 1
  fi

  # 2. Send the signal. `docker kill --signal=HUP` signals a running
  #    container; it is not a restart, which the state comparison pins.
  if ! docker kill --signal=HUP "$container" >/dev/null; then
    echo "probe: could not signal ${container}" >&2
    openbao_audit_restore_generation "$container" "$path" "$generation"
    return 1
  fi

  # 3. Poll for the configured path to reappear, bounded.
  waited=0
  while ! docker exec "$container" test -e "$path" 2>/dev/null; do
    if awk "BEGIN { exit !($waited >= $OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS) }"; then
      echo "probe: REFUTED — ${path} did not reappear within \
${OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS}s of SIGHUP; this image does not reopen its file audit \
device on the signal" >&2
      openbao_audit_restore_generation "$container" "$path" "$generation"
      return 1
    fi
    sleep "$OPENBAO_AUDIT_REOPEN_POLL_SECONDS"
    waited="$(awk "BEGIN { print $waited + $OPENBAO_AUDIT_REOPEN_POLL_SECONDS }")"
  done

  # 4. A *new inode* at the path, not the same file back under its old
  #    name. Presence alone is not the test.
  new_id="$(docker exec "$container" stat -c '%d:%i' "$path")" || {
    echo "probe: could not stat the reopened ${path}" >&2
    return 1
  }
  if [ "$new_id" = "$old_id" ]; then
    echo "probe: REFUTED — ${path} carries the renamed generation's own identity (${old_id})" >&2
    return 1
  fi

  # 5. Only now capture the generation's size, so writes OpenBao
  #    buffered *before* the reopen are not read as writes after it.
  gen_size="$(docker exec "$container" stat -c '%s' "$generation")" || return 1

  # 6. Drive one authenticated, non-mutating request whose audited path
  #    is unique to this run. A 403 or 404 is fine: the audit entry is
  #    what is asserted, and OpenBao writes the path into it in the
  #    clear.
  nonce="$(od -An -N8 -tx1 </dev/urandom | tr -d ' \n')"
  token="$(
    curl -sS -X POST -H 'Content-Type: application/json' \
      -d "{\"role_id\":\"${role_id}\",\"secret_id\":\"${secret_id}\"}" \
      "${url}/v1/auth/approle/login" | jq -r '.auth.client_token // empty'
  )"
  if [ -z "$token" ]; then
    echo "probe: the AppRole login returned no token" >&2
    return 1
  fi
  status="$(
    curl -sS -o /dev/null -w '%{http_code}' -H "X-Vault-Token: ${token}" \
      "${url}/v1/secret/data/bootroot-audit-reopen-probe/${nonce}"
  )"
  case "$status" in
    200 | 403 | 404) ;;
    *)
      echo "probe: the driven request answered ${status}" >&2
      return 1
      ;;
  esac

  # 7. Poll, bounded the same way, until the entry is in the new log.
  waited=0
  while ! docker exec "$container" grep -qF "$nonce" "$path" 2>/dev/null; do
    if awk "BEGIN { exit !($waited >= $OPENBAO_AUDIT_REOPEN_BUDGET_SECONDS) }"; then
      echo "probe: REFUTED — the driven request's entry never reached ${path}" >&2
      return 1
    fi
    sleep "$OPENBAO_AUDIT_REOPEN_POLL_SECONDS"
    waited="$(awk "BEGIN { print $waited + $OPENBAO_AUDIT_REOPEN_POLL_SECONDS }")"
  done

  # 8. And the renamed generation received nothing further — both
  #    halves pinned to the same request.
  if docker exec "$container" grep -qF "$nonce" "$generation"; then
    echo "probe: REFUTED — the renamed generation also received the driven request" >&2
    return 1
  fi
  gen_size_after="$(docker exec "$container" stat -c '%s' "$generation")" || return 1
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
  if docker exec "$container" test -e "$path" 2>/dev/null; then
    return 0
  fi
  docker exec "$container" mv -n "$generation" "$path" >/dev/null 2>&1 || true
}

# Asserts the reopen holds, failing the harness when it does not.
assert_openbao_audit_reopen() {
  openbao_audit_reopen_probe "$@" ||
    fail "openbao audit device does not reopen on SIGHUP; bootroot-agent's rotation would \
silently degrade to the lossy copy-and-truncate fallback on this image"
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
  local reference="$1" url="$2"
  local image standin status output

  image="$(docker inspect -f '{{.Config.Image}}' "$reference")" ||
    fail "could not read the image of ${reference}"
  standin="${reference}-reopen-probe-standin"
  docker rm -f "$standin" >/dev/null 2>&1 || true
  docker run -d --name "$standin" --entrypoint sh "$image" -c \
    'trap "" HUP; mkdir -p /openbao/audit; : > /openbao/audit/audit.log; while true; do sleep 1; done' \
    >/dev/null || fail "could not start the non-reopening stand-in"

  status=0
  # The run stops at the reappearance budget, before it reaches the
  # credentials, so those are placeholders.
  output="$(openbao_audit_reopen_probe "$standin" "$url" "role" "secret" 2>&1)" || status=$?
  docker rm -f "$standin" >/dev/null 2>&1 || true
  if [ "$status" -eq 0 ]; then
    fail "the openbao audit reopen probe passed a target that does not reopen; the check that \
guards the rotation mechanism cannot itself be trusted"
  fi
  case "$output" in
    *"did not reappear within"*) ;;
    *)
      fail "the openbao audit reopen probe refused the non-reopening stand-in for the wrong \
reason, so it is not the reopen evidence that would go red: ${output}"
      ;;
  esac
}
