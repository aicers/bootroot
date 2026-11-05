#!/usr/bin/env bash
#
# Validates the E2E harness's per-container mount comparison
# (`scripts/impl/lib/mount-check.sh`) without Docker and without
# bringing a stack up.
#
# `run-secrets-owner.sh` uses it to fail a root-run `infra up` that gave
# any container a mount it did not carry before. A green run never shows
# whether that check can fire: it only proves nothing was gained, which
# a comparison that silently stopped looking would prove just as well.
# The cases below feed it snapshots in `container_mounts`' format and
# compare what it prints, byte for byte, with what it must print.
#
# The library is sourced rather than copied, so this validates the
# shipped code.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LABEL="validate-e2e-mount-check"
IMPL_DIR="$ROOT_DIR/scripts/impl"
HARNESS="run-secrets-owner.sh"

# shellcheck source=impl/lib/mount-check.sh
. "$IMPL_DIR/lib/mount-check.sh"

die() {
  echo "[$LABEL] FAIL: $1" >&2
  exit 1
}

ok() {
  echo "[$LABEL] ok: $1"
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Runs `mounts_gained` on the fixture pair `$2`, compares its output
# exactly with `$3` (empty for none), and reports case `$1`.
expect_gained() {
  local name="$1" pair="$2" expected="$3" actual
  actual="$(mounts_gained "$WORK_DIR/$pair.before" "$WORK_DIR/$pair.after")" \
    || die "${name}: mounts_gained failed"
  [ "$actual" = "$expected" ] \
    || die "${name}: expected [${expected//$'\n'/; }], got [${actual//$'\n'/; }]"
  ok "$name"
}

# ---------------------------------------------------------------------------
# 1. A pair another container already held
# ---------------------------------------------------------------------------
#
# The project-wide union of mounts is the same before and after, so a
# comparison that discarded the container names would see nothing.
check_cross_container_gain() {
  printf '%s\n' \
    '/a privileged=false' \
    '  /x:/xa' \
    '/b privileged=false' \
    '  /y:/yb' >"$WORK_DIR/cross.before"
  printf '%s\n' \
    '/a privileged=false' \
    '  /x:/xa' \
    '  /y:/yb' \
    '/b privileged=false' \
    '  /y:/yb' >"$WORK_DIR/cross.after"
  expect_gained "a container gaining a pair another container held is caught" \
    cross '/a /y:/yb'
}

# ---------------------------------------------------------------------------
# 2. A pair no container held
# ---------------------------------------------------------------------------
check_new_pair_on_existing_container() {
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' \
    '/bootroot-ca privileged=false' \
    '  /srv/bootroot/secrets:/home/step' >"$WORK_DIR/new.before"
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' \
    '/bootroot-ca privileged=false' \
    '  /etc:/mnt/etc' \
    '  /srv/bootroot/secrets:/home/step' >"$WORK_DIR/new.after"
  expect_gained "a pair absent from the whole baseline is caught" \
    new '/bootroot-ca /etc:/mnt/etc'
}

# ---------------------------------------------------------------------------
# 3. A container present only after, with mounts
# ---------------------------------------------------------------------------
#
# One source path carries a space, which must survive into the report
# whole rather than be cut at the first field.
check_new_container_with_mounts() {
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' >"$WORK_DIR/added.before"
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' \
    '/bootroot-http01 privileged=false' \
    '  /srv/boot root/responder:/app/responder' \
    '  /srv/bootroot/certs:/app/certs' >"$WORK_DIR/added.after"
  expect_gained "a container present only after reports every mount, spaces intact" \
    added "/bootroot-http01 /srv/boot root/responder:/app/responder
/bootroot-http01 /srv/bootroot/certs:/app/certs"
}

# ---------------------------------------------------------------------------
# 4. A container present only after, with no mounts
# ---------------------------------------------------------------------------
check_new_container_without_mounts() {
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' >"$WORK_DIR/bare.before"
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' \
    '/bootroot-grafana privileged=false' >"$WORK_DIR/bare.after"
  expect_gained "a container present only after with no mounts gains nothing" bare ''
}

# ---------------------------------------------------------------------------
# 5. A container present only before
# ---------------------------------------------------------------------------
check_container_gone() {
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' \
    '/bootroot-prometheus privileged=false' \
    '  /srv/bootroot/prometheus:/etc/prometheus' \
    '  /var/lib/docker/volumes/prom:/prometheus' >"$WORK_DIR/gone.before"
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' >"$WORK_DIR/gone.after"
  expect_gained "a container present only before gains nothing" gone ''
}

# ---------------------------------------------------------------------------
# 6. Unchanged mounts, reordered
# ---------------------------------------------------------------------------
#
# `infra up` recreates every container, so the IDs differ and the order
# `docker ps` lists them in may too; the names and mounts do not.
check_reordered_unchanged() {
  printf '%s\n' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/openbao:/openbao/config' \
    '  /srv/bootroot/secrets/openbao:/openbao/tls' \
    '/bootroot-ca privileged=false' \
    '  /srv/boot root/secrets:/home/step' \
    '  /srv/bootroot/certs:/certs' >"$WORK_DIR/same.before"
  printf '%s\n' \
    '/bootroot-ca privileged=false' \
    '  /srv/bootroot/certs:/certs' \
    '  /srv/boot root/secrets:/home/step' \
    '/bootroot-openbao privileged=false' \
    '  /srv/bootroot/secrets/openbao:/openbao/tls' \
    '  /srv/bootroot/openbao:/openbao/config' >"$WORK_DIR/same.after"
  expect_gained "unchanged mounts, reordered by container and by mount, gain nothing" same ''
}

# ---------------------------------------------------------------------------
# A snapshot that was never written is not "nothing gained"
# ---------------------------------------------------------------------------
check_missing_snapshot() {
  : >"$WORK_DIR/present"
  ! mounts_gained "$WORK_DIR/present" "$WORK_DIR/absent" >/dev/null 2>&1 \
    || die "mounts_gained succeeded with no after snapshot"
  ! mounts_gained "$WORK_DIR/absent" "$WORK_DIR/present" >/dev/null 2>&1 \
    || die "mounts_gained succeeded with no before snapshot"
  ok "a missing snapshot fails the comparison rather than passing it"
}

# ---------------------------------------------------------------------------
# The harness uses the library, not a copy of its own
# ---------------------------------------------------------------------------
check_harness_wiring() {
  local path="$IMPL_DIR/$HARNESS"
  # shellcheck disable=SC2016 # matched literally against the harness text
  grep -q '^\. "\$SCRIPT_DIR/lib/mount-check\.sh"$' "$path" \
    || die "${HARNESS} does not source lib/mount-check.sh"
  # shellcheck disable=SC2016 # matched literally against the harness text
  grep -q 'mounts_gained "\$before" "\$after"' "$path" \
    || die "${HARNESS} does not compare its snapshots with mounts_gained"
  ! grep -q 'comm ' "$path" \
    || die "${HARNESS} still compares mounts inline with comm"
  ok "${HARNESS} sources the library and compares through mounts_gained"
}

check_cross_container_gain
check_new_pair_on_existing_container
check_new_container_with_mounts
check_new_container_without_mounts
check_container_gone
check_reordered_unchanged
check_missing_snapshot
check_harness_wiring

echo "[$LABEL] OK: the per-container mount comparison holds"
