# shellcheck shell=bash
# Per-container mount comparison for the Docker E2E harness.
#
# `run-secrets-owner.sh` snapshots every container of its Compose
# project before and after a root-run `infra up` (`container_mounts`),
# and fails the run if any container came out of it carrying a mount it
# did not carry going in.  A snapshot holds, per container, one
# unindented line `<name> privileged=<bool>`, where `<name>` is what
# `docker inspect -f '{{.Name}}'` prints (`/bootroot-openbao`), followed
# by that container's mounts as `  <source>:<destination>` lines with a
# two-space indent.
#
# The comparison is keyed by container name, never by container ID:
# `infra up` recreates containers, so their IDs change, while every
# bootroot container carries a fixed `container_name`.  Comparing the
# mounts alone, as the union across the whole project, misses a
# container that gained a pair another container already held.
#
# The function here never calls `fail` or `exit`: it prints what it
# found, and the caller decides what that means.

# Prints one `<name> <source>:<destination>` line per mount of snapshot
# file `$1`.  `<source>:<destination>` is the whole mount line with its
# two-space indent removed, not a whitespace-split field, so a path that
# contains a space survives intact.  Mount lines before any container
# line belong to no container and are dropped.
_mount_check_pairs() {
  awk '
    /^  / { if (name != "") print name " " substr($0, 3); next }
    /^[^ \t]/ { name = $1 }
  ' "$1"
}

# Prints every `<name> <source>:<destination>` pair that snapshot file
# `$2` (after) holds and snapshot file `$1` (before) does not, one per
# line in byte order, and nothing when there is none.  A container
# present only in `$2` contributes all of its pairs; one present only in
# `$1` contributes nothing.  The order of containers and of mounts in
# either file is irrelevant.
#
# Returns 0 whenever both files could be read, whatever it found;
# returns non-zero when either is missing or unreadable, so a snapshot
# that was never written is not read as "nothing gained".
mounts_gained() {
  local before="$1" after="$2"
  [ -r "$before" ] || return 1
  [ -r "$after" ] || return 1
  LC_ALL=C comm -13 \
    <(_mount_check_pairs "$before" | LC_ALL=C sort -u) \
    <(_mount_check_pairs "$after" | LC_ALL=C sort -u)
}
