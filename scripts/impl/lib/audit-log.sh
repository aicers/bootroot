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
