#!/usr/bin/env bash
#
# Validates the image handling of scripts/preflight/ci/deploy-no-build-smoke.sh
# without Docker, a registry or a bootroot build.
#
# The smoke itself runs against a real daemon, in local preflight and in
# CI's `test-core`, and a green run there only shows the happy path on
# that daemon's tag state. What it must also guarantee — that a moving
# tag can never stand in for a declared digest, and that every tag it
# touches is put back on failure, on INT/TERM, and is reported rather
# than silently left changed when that fails — only shows on the paths a
# green run never takes. Each case here drives the real smoke script
# against a fake `docker` holding a JSON image store
# (scripts/impl/lib/fake-docker-image-store.py) and a fake `bootroot`,
# then compares the tag store before and after.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LABEL="validate-deploy-no-build-smoke"
SMOKE="$ROOT_DIR/scripts/preflight/ci/deploy-no-build-smoke.sh"
FAKE_DOCKER="$ROOT_DIR/scripts/impl/lib/fake-docker-image-store.py"

die() {
  echo "[$LABEL] FAIL: $1" >&2
  exit 1
}

ok() {
  echo "[$LABEL] ok: $1"
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

BIN_DIR="$WORK_DIR/bin"
mkdir -p "$BIN_DIR"
# The root of the smoke's lock directory, so no case here contends with
# a real smoke running on this host.
LOCK_ROOT="$WORK_DIR/lock-root"
LOCK_DIR="$LOCK_ROOT/bootroot-deploy-smoke-$(id -u)"
mkdir -m 700 "$LOCK_ROOT" "$LOCK_DIR"
ln -s "$FAKE_DOCKER" "$BIN_DIR/docker"

# `infra install --no-build`, as far as the smoke can observe it: load
# every archive, then bring the default services up with no pull and no
# build.
cat >"$BIN_DIR/bootroot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *" --help "*)
    echo "      --no-build  Use prebuilt images only"
    exit 0
    ;;
esac
archive_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --image-archive-dir) archive_dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
for archive in "$archive_dir"/*.tar; do
  docker load -i "$archive"
done
docker compose -f docker-compose.deploy.yml -p "${COMPOSE_PROJECT_NAME:-bootroot}" \
  up --no-build --pull never -d openbao postgres step-ca bootroot-http01
EOF
chmod +x "$BIN_DIR/bootroot"

cat >"$BIN_DIR/cargo" <<'EOF'
#!/bin/sh
echo "fake cargo: the smoke must not build during this validation" >&2
exit 1
EOF
chmod +x "$BIN_DIR/cargo"

PINS="$(python3 scripts/runtime_images.py --declaration deploy/runtime-images.json pins)"
VERSION="$(awk -F' = ' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' Cargo.toml)"
OPENBAO_TAG="$(awk -F'\t' '$1 == "openbao" { print $5 }' <<<"$PINS")"
POSTGRES_TAG="$(awk -F'\t' '$1 == "postgres" { print $5 }' <<<"$PINS")"
STEPCA_TAG="$(awk -F'\t' '$1 == "step-ca" { print $5 }' <<<"$PINS")"
# The shared tag a source build writes; the smoke builds under a tag
# private to its run instead, and must leave this one alone.
RESPONDER_LATEST="bootroot-http01-responder:latest"
RESPONDER_RELEASE="bootroot-http01-responder:$VERSION"
# The responder Dockerfile's two stages: the build base, which the fake
# build refreshes only under the classic builder, and the runtime base.
BASES="$(awk 'toupper($1) == "FROM" { print $2 }' docker/http01-responder/Dockerfile)"
BUILD_BASE="$(sed -n 1p <<<"$BASES")"
RUNTIME_BASE="$(sed -n 2p <<<"$BASES")"
[ -n "$BUILD_BASE" ] && [ -n "$RUNTIME_BASE" ] ||
  die "expected two FROM stages in docker/http01-responder/Dockerfile, found: $BASES"

# Four ports nothing listens on, for the smoke's own port preflight.
read -r PORT_A PORT_B PORT_C PORT_D < <(python3 -c '
import socket
socks = [socket.socket() for _ in range(4)]
for s in socks:
    s.bind(("127.0.0.1", 0))
print(" ".join(str(s.getsockname()[1]) for s in socks))
')

id_of() {
  python3 -c 'import hashlib, sys; print("sha256:" + hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"
}

# new_state <case> — a fresh store: the registry serves each declared pin
# as an amd64+arm64 index, plus a moving tag for postgres that must never
# be used; the tag store starts empty.
new_state() {
  STATE="$WORK_DIR/state-$1"
  mkdir -p "$STATE"
  python3 - "$STATE" <<'EOF' "$PINS"
import hashlib
import json
import sys

state, pins = sys.argv[1], sys.argv[2]


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


registry = {}
for line in pins.splitlines():
    role, repository, tag, pinned, lookup = line.split("\t")
    index = pinned
    amd64, arm64 = digest(f"{role}-amd64"), digest(f"{role}-arm64")
    registry[f"{repository}@{pinned}"] = {
        "target": index,
        "images": {
            index: {"platform": "index", "children": {"linux/amd64": amd64, "linux/arm64": arm64}},
            amd64: {"platform": "linux/amd64"},
            arm64: {"platform": "linux/arm64"},
        },
    }
moving = digest("postgres-moving-tag")
for ref in ("postgres:18.4", "docker.io/library/postgres:18.4"):
    registry[ref] = {"target": moving, "images": {moving: {"platform": "linux/amd64"}}}
with open(f"{state}/registry.json", "w") as handle:
    json.dump(registry, handle)
EOF
}

# seed <tag> <id> — a tag that exists before the smoke.
seed() {
  python3 - "$STATE" "$1" "$2" <<'EOF'
import json
import sys

state, tag, image_id = sys.argv[1:]
path = f"{state}/tags.json"
try:
    tags = json.load(open(path))
except FileNotFoundError:
    tags = {}
images_path = f"{state}/images.json"
try:
    images = json.load(open(images_path))
except FileNotFoundError:
    images = {}
tags[tag] = image_id
images.setdefault(image_id, {"platform": "linux/amd64"})
json.dump(tags, open(path, "w"))
json.dump(images, open(images_path, "w"))
EOF
}

# The tag store minus the `repository@digest` references a digest pull
# leaves behind by design.
tag_map() {
  python3 - "$STATE" <<'EOF'
import json
import sys

try:
    tags = json.load(open(f"{sys.argv[1]}/tags.json"))
except FileNotFoundError:
    tags = {}
for name in sorted(tags):
    if "@" not in name:
        print(f"{name} {tags[name]}")
EOF
}

# run_smoke — runs the smoke against the current state; sets STATUS and
# OUTPUT. Caller image overrides are exported on purpose: the smoke must
# ignore every one of them.
run_smoke() {
  STATUS=0
  OUTPUT="$(
    PATH="$BIN_DIR:$PATH" \
      FAKE_DOCKER_STATE="$STATE" \
      FAKE_DOCKER_BUILD_BASE="$BUILD_BASE" \
      BOOTROOT_DEPLOY_SMOKE_LOCK_ROOT="${SMOKE_LOCK_ROOT:-$LOCK_ROOT}" \
      TMPDIR="${SMOKE_TMPDIR:-${TMPDIR:-/tmp}}" \
      BOOTROOT_BIN="$BIN_DIR/bootroot" \
      COMPOSE_PROJECT_NAME=deploy-smoke-fake \
      OPENBAO_HOST_PORT="$PORT_A" STEPCA_HOST_PORT="$PORT_B" \
      HTTP01_ADMIN_HOST_PORT="$PORT_C" POSTGRES_HOST_PORT="$PORT_D" \
      OPENBAO_IMAGE=openbao/openbao:9.9.9 \
      POSTGRES_IMAGE=postgres:99 \
      BOOTROOT_STEP_CA_IMAGE=smallstep/step-ca:9.9.9 \
      BOOTROOT_HTTP01_IMAGE=example.invalid/unrelated:1 \
      bash "$SMOKE" 2>&1
  )" || STATUS=$?
}

expect_status() {
  local name="$1" expected="$2"
  if [ "$STATUS" -ne "$expected" ]; then
    printf '%s\n' "$OUTPUT" >&2
    die "$name: expected exit $expected, got $STATUS"
  fi
}

expect_output() {
  local name="$1" fragment="$2"
  if ! grep -qF -- "$fragment" <<<"$OUTPUT"; then
    printf '%s\n' "$OUTPUT" >&2
    die "$name: output did not contain: $fragment"
  fi
}

expect_no_output() {
  local name="$1" fragment="$2"
  if grep -qF -- "$fragment" <<<"$OUTPUT"; then
    printf '%s\n' "$OUTPUT" >&2
    die "$name: output unexpectedly contained: $fragment"
  fi
}

expect_restored() {
  local name="$1" after
  after="$(tag_map)"
  if [ "$after" != "$BEFORE" ]; then
    printf 'before:\n%s\nafter:\n%s\n' "$BEFORE" "$after" >&2
    die "$name: the tag store after cleanup differs from before the smoke"
  fi
}

# No pull of anything but a declared digest, for the release platform.
expect_digest_pulls_only() {
  local name="$1" pulls
  pulls="$(grep -E '^pull ' "$STATE/argv.log" || true)"
  if grep -vE '^pull --platform linux/amd64 [^ ]+@sha256:[0-9a-f]{64}$' <<<"$pulls" | grep -q .; then
    printf '%s\n' "$pulls" >&2
    die "$name: the smoke pulled something other than a declared digest"
  fi
}

seed_mixed() {
  # Present before: openbao's lookup tag on an unrelated image, postgres's
  # on the registry's moving tag (a stale tag pull), the responder's
  # `:latest` and the build base. Absent before: step-ca's lookup tag,
  # the responder release tag and the runtime base.
  seed "$OPENBAO_TAG" "$(id_of prior-openbao)"
  seed "$POSTGRES_TAG" "$(id_of postgres-moving-tag)"
  seed "$RESPONDER_LATEST" "$(id_of prior-responder)"
  seed "$BUILD_BASE" "$(id_of prior-build-base)"
  BEFORE="$(tag_map)"
}

# ---------------------------------------------------------------------------
# Success, with previously present and previously absent tags
# ---------------------------------------------------------------------------

new_state success-mixed
seed_mixed
run_smoke
expect_status "success" 0
expect_output "success" "deploy compose no-build smoke passed"
expect_output "success" "restored: every managed tag maps as before the smoke"
expect_restored "success"
expect_digest_pulls_only "success"
for tag in "$OPENBAO_TAG" "$POSTGRES_TAG" "$STEPCA_TAG" \
  "bootroot-http01-responder:smoke-build-" "$RESPONDER_RELEASE" "$BUILD_BASE" "$RUNTIME_BASE"; do
  expect_output "success" "snapshot: $tag"
done
grep -qE "^compose .* build bootroot-http01$" "$STATE/argv.log" ||
  die "success: the responder was not built"
ok "success restores present tags and removes created ones"

# The moving tag never replaced the pin: postgres's lookup tag was saved
# while it named the pin's amd64 image, and the container ran that image.
POSTGRES_AMD64="$(id_of postgres-amd64)"
expect_output "moving tag" "record: dependency=postgres pin=docker.io/library/postgres@sha256:"
expect_output "moving tag" "lookup=$POSTGRES_TAG image-id=$POSTGRES_AMD64"
expect_output "moving tag" "running: postgres container runs $POSTGRES_AMD64 (linux/amd64)"
expect_no_output "moving tag" "$(id_of postgres-moving-tag) (linux/amd64)"
ok "a moving tag cannot replace the digest pull"

# Save and load go through the lookup tags the Compose defaults name.
for pair in "openbao:$OPENBAO_TAG" "postgres:$POSTGRES_TAG" "step-ca:$STEPCA_TAG"; do
  role="${pair%%:*}"
  tag="${pair#*:}"
  grep -qE "^save --platform linux/amd64 -o [^ ]*/$role\\.tar $tag$" "$STATE/argv.log" ||
    die "save/load: $role was not saved from its lookup tag $tag"
  grep -qE "^load -i [^ ]*/$role\\.tar$" "$STATE/argv.log" ||
    die "save/load: $role.tar was not loaded"
done
grep -qE "^save -o [^ ]*/http01\\.tar $RESPONDER_RELEASE$" "$STATE/argv.log" ||
  die "save/load: the responder was not saved from $RESPONDER_RELEASE"
ok "save/load use the required lookup tags"

new_state success-absent
BEFORE="$(tag_map)"
run_smoke
expect_status "success from an empty store" 0
expect_restored "success from an empty store"
ok "success from an empty store leaves no tag behind"

# ---------------------------------------------------------------------------
# Failure partway through preparation
# ---------------------------------------------------------------------------

new_state missing-pin
seed_mixed
FAKE_DOCKER_FAIL_ON='^pull .*postgres@sha256:' run_smoke
expect_status "missing pin" 1
expect_output "missing pin" "is not available for linux/amd64; there is no fallback to the tag"
expect_restored "missing pin"
expect_digest_pulls_only "missing pin"
ok "a missing pin fails hard, with no tag fallback, and restores"

new_state partial
seed_mixed
FAKE_DOCKER_FAIL_ON='^save .*/step-ca\.tar ' run_smoke
expect_status "partial preparation failure" 1
expect_restored "partial preparation failure"
ok "a failure after tags changed restores them"

# The snapshot creates a backup tag for postgres's prior image, and the
# command then fails or is interrupted: the backup is still this run's to
# remove. `expect_restored` sees backup tags, so one left behind fails it.
BACKUP_POSTGRES="^tag $(id_of postgres-moving-tag) bootroot-deploy-smoke-backup:[^ ]+\$"
new_state backup-fails-after
seed_mixed
FAKE_DOCKER_AFTER_ON="$BACKUP_POSTGRES=FAIL" run_smoke
expect_status "backup tag failure after creating it" 1
expect_no_output "backup tag failure after creating it" "after cleanup the backup tag"
expect_restored "backup tag failure after creating it"
ok "a backup tag created by a command that then failed is removed"

new_state backup-int-after
seed_mixed
FAKE_DOCKER_AFTER_ON="$BACKUP_POSTGRES=INT" run_smoke
expect_status "INT after a backup tag was created" 130
expect_restored "INT after a backup tag was created"
ok "a backup tag created just before INT is removed"

# The build names its private tag, then fails: whatever that tag names
# is this run's to remove.
new_state build-fails-after
seed_mixed
FAKE_DOCKER_AFTER_ON='^compose .* build bootroot-http01$=FAIL' run_smoke
expect_status "build failure after tagging" 1
expect_no_output "build failure after tagging" "which this run never set"
expect_restored "build failure after tagging"
ok "a build that tagged its image and then failed restores"

# A caller asking for the classic builder, which would refresh the base
# tags, does not get it: the smoke builds with BuildKit.
new_state classic-builder-requested
seed_mixed
DOCKER_BUILDKIT=0 run_smoke
expect_status "classic builder requested" 0
expect_restored "classic builder requested"
ok "the build runs under BuildKit whatever the caller exported"

new_state retag-fails-after
seed_mixed
FAKE_DOCKER_AFTER_ON="^tag [^ ]*@sha256:[0-9a-f]+ $STEPCA_TAG\$=FAIL" run_smoke
expect_status "retag failure after the change" 1
expect_no_output "retag failure after the change" "which this run never set"
expect_restored "retag failure after the change"
ok "a retag that changed its tag and then failed restores it"

# The install loads an archive, repointing its lookup tag, then fails.
new_state load-fails-after
seed_mixed
FAKE_DOCKER_AFTER_ON='^load -i .*/postgres\.tar$=FAIL' run_smoke
expect_status "install failure after a load" 1
expect_no_output "install failure after a load" "which this run never set"
expect_restored "install failure after a load"
ok "an install that loaded archives and then failed restores"

# ---------------------------------------------------------------------------
# Catchable interruption
# ---------------------------------------------------------------------------

new_state term
seed_mixed
FAKE_DOCKER_SIGNAL_ON='^save .*/postgres\.tar =TERM' run_smoke
expect_status "TERM" 143
expect_restored "TERM"
ok "TERM mid-preparation restores"

new_state int
seed_mixed
FAKE_DOCKER_SIGNAL_ON='^compose .* build bootroot-http01$=INT' run_smoke
expect_status "INT" 130
expect_restored "INT"
ok "INT during the responder build restores"

new_state int-after-build
seed_mixed
FAKE_DOCKER_AFTER_ON='^compose .* build bootroot-http01$=INT' run_smoke
expect_status "INT after the build tagged" 130
expect_no_output "INT after the build tagged" "which this run never set"
expect_restored "INT after the build tagged"
ok "INT after the build tagged its image restores"

# ---------------------------------------------------------------------------
# Restoration failure
# ---------------------------------------------------------------------------

new_state restore-fails
seed_mixed
FAKE_DOCKER_FAIL_ON="^tag sha256:[0-9a-f]+ $POSTGRES_TAG\$" run_smoke
expect_status "restoration failure" 1
expect_output "restoration failure" "cannot point $POSTGRES_TAG back at"
expect_output "restoration failure" "after cleanup $POSTGRES_TAG names"
expect_no_output "restoration failure" "deploy compose no-build smoke passed"
ok "a restoration failure is reported and fails a passing smoke"

new_state restore-fails-after-term
seed_mixed
FAKE_DOCKER_SIGNAL_ON='^save .*/step-ca\.tar =TERM' \
  FAKE_DOCKER_FAIL_ON="^tag sha256:[0-9a-f]+ $POSTGRES_TAG\$" run_smoke
expect_status "restoration failure after TERM" 143
expect_output "restoration failure after TERM" "cannot point $POSTGRES_TAG back at"
expect_output "restoration failure after TERM" "smoke cleanup failed"
ok "a restoration failure keeps the original failure's status"

new_state created-tag-removal-fails
seed_mixed
FAKE_DOCKER_FAIL_ON="^image rm $STEPCA_TAG\$" run_smoke
expect_status "created tag removal failure" 1
expect_output "created tag removal failure" "cannot remove $STEPCA_TAG, which this run created"
ok "failing to remove a created tag is reported"

# ---------------------------------------------------------------------------
# Teardown failure
# ---------------------------------------------------------------------------

# The pre-run reset issues the same `down` and tolerates its failure;
# the teardown of the staged stack must not.
new_state teardown-fails
seed_mixed
FAKE_DOCKER_FAIL_ON='^compose -p [^ ]+ -f docker-compose\.deploy\.yml down ' run_smoke
expect_status "teardown failure" 1
expect_output "teardown failure" "cannot stop the test stack (Compose project deploy-smoke-fake)"
expect_output "teardown failure" "smoke cleanup failed"
expect_no_output "teardown failure" "deploy compose no-build smoke passed"
expect_restored "teardown failure"
ok "a test stack that cannot be stopped fails the smoke"

new_state teardown-fails-after-term
seed_mixed
FAKE_DOCKER_SIGNAL_ON='^save .*/step-ca\.tar =TERM' \
  FAKE_DOCKER_FAIL_ON='^compose -p [^ ]+ -f docker-compose\.deploy\.yml down ' run_smoke
expect_status "teardown failure after TERM" 143
ok "a teardown failure keeps the original failure's status"

# ---------------------------------------------------------------------------
# Another writer changes a managed tag during the smoke
# ---------------------------------------------------------------------------

FOREIGN="$(id_of foreign-writer)"
new_state conflict
seed_mixed
FAKE_DOCKER_FOREIGN_ON="^container inspect=$OPENBAO_TAG=$FOREIGN" run_smoke
expect_status "concurrent writer" 1
# The lookup tag no longer names the image the container runs, and the
# smoke compares the two rather than only logging the loaded ID.
expect_output "concurrent writer" "the loaded openbao image is $FOREIGN, but the openbao container runs $(id_of openbao-amd64)"
expect_output "concurrent writer" "$OPENBAO_TAG now names $FOREIGN, which this run never set"
grep -qx "$OPENBAO_TAG $FOREIGN" <<<"$(tag_map)" ||
  die "concurrent writer: the other writer's mapping was overwritten"
expect_output "concurrent writer" "still held as bootroot-deploy-smoke-backup:"
grep -q "^bootroot-deploy-smoke-backup:[^ ]* $(id_of prior-openbao)$" <<<"$(tag_map)" ||
  die "concurrent writer: the prior image lost the backup tag holding it"
[ "$(tag_map | grep -v "^$OPENBAO_TAG \|^bootroot-deploy-smoke-backup:")" = \
  "$(grep -v "^$OPENBAO_TAG " <<<"$BEFORE")" ] ||
  die "concurrent writer: the other tags were not restored"
ok "a tag another writer changed is reported and left alone"

# Another writer changes a tag a command never reaches, and that command
# then fails: the change is not this run's, whatever was in progress.
# `expect_foreign_kept <case> <tag>` checks it was reported and kept,
# and that every other tag was restored.
expect_foreign_kept() {
  local name="$1" tag="$2"
  expect_status "$name" 1
  expect_output "$name" "$tag now names $FOREIGN, which this run never set"
  grep -qx "$tag $FOREIGN" <<<"$(tag_map)" ||
    die "$name: the other writer's mapping of $tag was overwritten"
  [ "$(tag_map | grep -v "^$tag ")" = "$(grep -v "^$tag " <<<"$BEFORE")" ] ||
    die "$name: the other tags were not restored"
}

new_state conflict-during-failed-build
seed_mixed
FAKE_DOCKER_FOREIGN_ON="^compose .* build bootroot-http01\$=$RUNTIME_BASE=$FOREIGN" \
  FAKE_DOCKER_AFTER_ON='^compose .* build bootroot-http01$=FAIL' run_smoke
expect_foreign_kept "base changed during a failed build" "$RUNTIME_BASE"
ok "a base tag another writer changed during a failed build is left alone"

new_state conflict-during-failed-install
seed_mixed
FAKE_DOCKER_FOREIGN_ON="^load -i .*/postgres\.tar\$=$STEPCA_TAG=$FOREIGN" \
  FAKE_DOCKER_AFTER_ON='^load -i .*/postgres\.tar$=FAIL' run_smoke
expect_foreign_kept "lookup tag changed during a failed install" "$STEPCA_TAG"
ok "a lookup tag another writer changed during a failed install is left alone"

# ---------------------------------------------------------------------------
# Only one smoke runs at a time
# ---------------------------------------------------------------------------

# run_smoke_while_locked <lock file> — runs the smoke while another
# process holds an exclusive `flock` on `lock file`, releasing it once
# the run has ended.
run_smoke_while_locked() {
  local lock="$1" ready="$WORK_DIR/lock-ready.fifo" release="$WORK_DIR/lock-release.fifo"
  local holder
  rm -f "$ready" "$release"
  mkfifo "$ready" "$release"
  # Both opened read-write, which never blocks, so a holder that dies
  # early makes the `read` below time out rather than hang.
  exec 7<>"$ready" 6<>"$release"
  python3 - "$lock" "$ready" "$release" <<'EOF' &
import fcntl
import sys

lock, ready, release = sys.argv[1:]
handle = open(lock, "a")
fcntl.flock(handle, fcntl.LOCK_EX)
with open(ready, "w") as signal:
    signal.write("held\n")
with open(release) as wait:
    wait.readline()
EOF
  holder=$!
  read -t 30 -r _ <&7 || die "the lock holder never took $lock"
  run_smoke
  echo release >&6
  wait "$holder" || die "the lock holder for $lock failed"
  exec 6>&- 7>&-
}

# expect_refused_by_lock <name> — the run was refused on the lock before
# it ran a single `docker` command.
expect_refused_by_lock() {
  local name="$1"
  expect_status "$name" 1
  expect_output "$name" "another deploy no-build smoke run holds"
  [ ! -s "$STATE/argv.log" ] || {
    cat "$STATE/argv.log" >&2
    die "$name: the refused run invoked docker"
  }
  expect_restored "$name"
}

# Another run holds the smoke's lock: this one is refused before it runs
# a single `docker` command, so it neither stops that run's stack nor
# changes a tag it is using.
new_state lock-held
seed_mixed
run_smoke_while_locked "$LOCK_DIR/deploy-no-build-smoke.lock"
expect_refused_by_lock "lock held"
ok "a smoke started while another holds the lock is refused before touching docker"

# The lock's path does not follow `$TMPDIR`, which differs per session on
# macOS: a run under one takes the lock that a run under another is then
# refused on.
new_state lock-tmpdir-a
seed_mixed
mkdir -p "$WORK_DIR/tmpdir-a" "$WORK_DIR/tmpdir-b"
SMOKE_TMPDIR="$WORK_DIR/tmpdir-a" run_smoke
expect_status "lock under one TMPDIR" 0
HELD_LOCK="$(sed -n 's/^\[deploy-no-build-smoke\] lock: holding //p' <<<"$OUTPUT")"
[ "$HELD_LOCK" = "$LOCK_DIR/deploy-no-build-smoke.lock" ] || {
  printf '%s\n' "$OUTPUT" >&2
  die "lock under one TMPDIR: held '$HELD_LOCK', not the fixed lock path"
}
# Nor does the default, which no case above reaches: resolved under two
# TMPDIR values with no root override, it is the same fixed path. Only
# resolved, never taken, so a real smoke holding it is undisturbed.
default_lock_dir() {
  # shellcheck disable=SC2016 # expanded by the child shell, not here
  env -u BOOTROOT_DEPLOY_SMOKE_LOCK_ROOT TMPDIR="$1" PATH="$BIN_DIR:$PATH" \
    bash -c 'source "$1" && init_smoke && rm -rf "$STAGE_DIR" && printf "%s" "$LOCK_DIR"' \
    _ "$SMOKE"
}
DEFAULT_A="$(default_lock_dir "$WORK_DIR/tmpdir-a")" || die "default lock: init_smoke failed"
DEFAULT_B="$(default_lock_dir "$WORK_DIR/tmpdir-b")" || die "default lock: init_smoke failed"
[ "$DEFAULT_A" = "/tmp/bootroot-deploy-smoke-$(id -u)" ] && [ "$DEFAULT_B" = "$DEFAULT_A" ] ||
  die "default lock: resolved '$DEFAULT_A' and '$DEFAULT_B', not /tmp/bootroot-deploy-smoke-$(id -u) for both"
new_state lock-tmpdir-b
seed_mixed
SMOKE_TMPDIR="$WORK_DIR/tmpdir-b" run_smoke_while_locked "$HELD_LOCK"
expect_refused_by_lock "lock under another TMPDIR"
ok "runs under different TMPDIR values contend for the same lock"

# Released when the holder ends, so the next run takes it.
new_state lock-released
seed_mixed
run_smoke
expect_status "lock released" 0
expect_restored "lock released"
ok "the lock is free again once its holder ends"

# A lock directory others can write to is one where the lock file's
# inode can be swapped, so it is refused.
new_state lock-dir-open
seed_mixed
mkdir -p "$WORK_DIR/open-root/bootroot-deploy-smoke-$(id -u)"
chmod 777 "$WORK_DIR/open-root/bootroot-deploy-smoke-$(id -u)"
SMOKE_LOCK_ROOT="$WORK_DIR/open-root" run_smoke
expect_status "lock directory open to others" 1
expect_output "lock directory open to others" "is not a directory private to this user"
[ ! -s "$STATE/argv.log" ] || die "lock directory open to others: the refused run invoked docker"
ok "a lock directory open to other users is refused"

echo "[$LABEL] OK: pinned preparation and tag restoration behave on every path"
