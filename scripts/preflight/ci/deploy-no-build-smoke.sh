#!/usr/bin/env bash
#
# Deploy compose no-build smoke: prepares an air-gapped payload the way a
# release does, then installs it from a staged directory with no source
# tree, no pulls and no builds.
#
# The three registry images are pulled by the exact digests
# deploy/runtime-images.json approves, for the release platform only —
# never by tag, and with no fallback to the tag when the pin is missing.
# Each is tagged locally with the lookup tag the Compose defaults and the
# step-ca helpers name, saved, and loaded back by `infra install`. The
# smoke records each pin's selected image ID and platform before export
# and asserts that the started container runs exactly that image.
#
# Caller image overrides (`OPENBAO_IMAGE` and the rest) are ignored: the
# images under test are the declared ones, and an override must not make
# this smoke pull or tag something else.
#
# Every tag the run may change is snapshotted before the first pull,
# build, retag or load — the three lookup tags, the responder's build and
# release tags, and the responder Dockerfile's base images — and restored
# on every exit path the shell can catch (success, failure, INT, TERM):
# a tag that existed is pointed back at its prior image, one this run
# created is removed by name. Prior images are held by a backup tag for
# the duration, and nothing is ever deleted by image ID, force-removed or
# pruned. Each command that may repoint a managed tag is bracketed, so a
# tag it changed before failing or being interrupted still counts as
# this run's. A tag some other writer changed during the run is reported
# and left alone. The mappings are read back after cleanup and the smoke
# fails unless they equal the snapshot. A test stack that cannot be
# stopped fails the smoke too. SIGKILL cannot be caught, and nothing is
# promised for it.
#
# Pulling by digest leaves a `repository@digest` reference behind. It is
# not removed: in the containerd image store, removing a digest reference
# removes every tag naming the same image, including tags that predate
# this run.
#
# `down -v` on the test project is destructive. Never point this at a
# live installation's Compose project.
set -euo pipefail

SMOKE_PLATFORM="linux/amd64"
BACKUP_REPOSITORY="bootroot-deploy-smoke-backup"
RESPONDER_REPOSITORY="bootroot-http01-responder"
RESPONDER_DOCKERFILE="docker/http01-responder/Dockerfile"

log() {
  printf "[deploy-no-build-smoke] %s\n" "$*"
}

fail() {
  printf "[deploy-no-build-smoke] ERROR: %s\n" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

init_smoke() {
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  cd "$ROOT_DIR"

  BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
  BOOTROOT_VERSION="$(
    awk -F' = ' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' Cargo.toml
  )"
  RESPONDER_BUILD_TAG="$RESPONDER_REPOSITORY:latest"
  RESPONDER_RELEASE_TAG="$RESPONDER_REPOSITORY:$BOOTROOT_VERSION"

  # The install under test resolves its Compose project from
  # `COMPOSE_PROJECT_NAME` when exported and falls back to the literal
  # `bootroot`, so mirror that order here rather than hard-coding one side.
  COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-bootroot}"

  STAGE_DIR="$(mktemp -d)"
  ARCHIVE_DIR="$STAGE_DIR/images"
  SHIM_DIR="$STAGE_DIR/bin"
  DOCKER_LOG="$STAGE_DIR/docker-argv.log"
  REAL_DOCKER="$(command -v docker)"
  RUN_ID="$(date +%s)-$$"

  # One line per declared dependency:
  # role, repository, tag, digest, lookup tag.
  PINS="$(
    python3 "$ROOT_DIR/scripts/runtime_images.py" \
      --declaration "$ROOT_DIR/deploy/runtime-images.json" \
      --platform "$SMOKE_PLATFORM" pins
  )" || fail "deploy/runtime-images.json does not validate"
  [ -n "$PINS" ] || fail "deploy/runtime-images.json declares no dependencies"

  # Per managed tag, parallel arrays: the tag, its prior image ID ("" when
  # it did not exist), the backup tag holding that image, and the image
  # IDs this run itself may have pointed it at.
  MANAGED_TAGS=()
  PRIOR_IDS=()
  BACKUP_TAGS=()
  OURS_IDS=()
  # Per declared dependency, the image ID selected for the platform.
  SELECTED_ROLES=()
  SELECTED_IDS=()
  # The managed tags the command now running may repoint; see `mutating`.
  IN_FLIGHT_TAGS=()
  CLEANED=0
}

lookup_tag_of() {
  awk -F'\t' -v role="$1" '$1 == role { print $5 }' <<<"$PINS"
}

# Prints the image ID `ref` names, or nothing when it does not exist.
# Any other inspect failure is an error: an unreadable tag state must not
# pass for an absent one.
image_id_of() {
  local out status=0
  out="$(docker image inspect --format '{{.Id}}' "$1" 2>&1)" || status=$?
  if [ "$status" -eq 0 ]; then
    printf '%s' "$out"
    return 0
  fi
  if grep -qi 'no such image' <<<"$out"; then
    return 0
  fi
  printf '%s\n' "$out" >&2
  return 1
}

# True when `docker` rejected a `--platform` flag it or its daemon does
# not support, as opposed to failing for any other reason.
platform_flag_unsupported() {
  grep -qiE 'unknown flag: --platform|requires API version|not supported' <<<"$1"
}

# Prints `<id>\t<os/arch[/variant]>\t<RepoDigests, comma-separated>` for
# the `SMOKE_PLATFORM` image `ref` resolves to. A daemon too old for
# `inspect --platform` stores one platform per image, so the plain
# inspect answers the same question there.
inspect_selected() {
  local ref="$1" json status=0
  json="$(docker image inspect --platform "$SMOKE_PLATFORM" "$ref" 2>&1)" || status=$?
  if [ "$status" -ne 0 ]; then
    if ! platform_flag_unsupported "$json"; then
      printf '%s\n' "$json" >&2
      return 1
    fi
    json="$(docker image inspect "$ref")" || return 1
  fi
  python3 -c '
import json, sys
image = json.load(sys.stdin)[0]
platform = "/".join(p for p in (image.get("Os"), image.get("Architecture"), image.get("Variant")) if p)
print("\t".join((image["Id"], platform, ",".join(image.get("RepoDigests") or []))))
' <<<"$json"
}

save_selected_platform() {
  local out="$1" ref="$2" err status=0
  err="$(docker save --platform "$SMOKE_PLATFORM" -o "$out" "$ref" 2>&1)" || status=$?
  if [ "$status" -ne 0 ]; then
    platform_flag_unsupported "$err" || {
      printf '%s\n' "$err" >&2
      return 1
    }
    docker save -o "$out" "$ref"
  fi
}

managed_index_of() {
  local i
  [ "${#MANAGED_TAGS[@]}" -gt 0 ] || return 1
  for i in "${!MANAGED_TAGS[@]}"; do
    if [ "${MANAGED_TAGS[$i]}" = "$1" ]; then
      printf '%s' "$i"
      return 0
    fi
  done
  return 1
}

# Adds `id` to the image IDs this run may have pointed `tag` at.
record_ours() {
  local index
  index="$(managed_index_of "$1")" || fail "internal: $1 is not a managed tag"
  OURS_IDS[index]="${OURS_IDS[index]} $2"
}

# Records whatever the in-flight tags now name as this run's. Returns
# nonzero, having reported why, when a tag cannot be read; the restore
# that follows reports that tag again.
claim_in_flight_tags() {
  local tag id failed=0
  [ "${#IN_FLIGHT_TAGS[@]}" -gt 0 ] || return 0
  for tag in "${IN_FLIGHT_TAGS[@]}"; do
    if ! id="$(image_id_of "$tag")"; then
      printf '[deploy-no-build-smoke] ERROR: cannot read the image %s now names\n' "$tag" >&2
      failed=1
      continue
    fi
    [ -z "$id" ] || record_ours "$tag" "$id"
  done
  IN_FLIGHT_TAGS=()
  return "$failed"
}

# mutating <tag>... -- <command>...: runs a command that may repoint the
# named managed tags and records what they then name as this run's. The
# tags are marked in flight first, so a command that changes one and
# then fails, or is interrupted by INT or TERM, leaves cleanup to record
# them: its change is this run's to undo, not another writer's.
mutating() {
  local tags=()
  while [ "$1" != "--" ]; do
    tags+=("$1")
    shift
  done
  shift
  IN_FLIGHT_TAGS=("${tags[@]}")
  "$@"
  claim_in_flight_tags || fail "cannot record the tags $* changed"
}

managed_tag_list() {
  cut -f5 <<<"$PINS"
  printf '%s\n' "$RESPONDER_BUILD_TAG" "$RESPONDER_RELEASE_TAG"
  # The responder build may pull or refresh its base images, and a
  # containerd image store records those under their tags.
  awk 'toupper($1) == "FROM" { print $2 }' "$RESPONDER_DOCKERFILE"
}

# Captures every managed tag's current image ID, or its absence, before
# anything can change one. A tag that exists gets a backup tag on the
# same image so the image survives being untagged in the meantime.
snapshot_tags() {
  local tag id backup
  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    if managed_index_of "$tag" >/dev/null; then
      continue
    fi
    id="$(image_id_of "$tag")" || fail "cannot read the image $tag names before the smoke"
    backup=""
    if [ -n "$id" ]; then
      backup="$BACKUP_REPOSITORY:$RUN_ID-${#MANAGED_TAGS[@]}"
    fi
    MANAGED_TAGS+=("$tag")
    PRIOR_IDS+=("$id")
    BACKUP_TAGS+=("")
    OURS_IDS+=("")
    if [ -n "$backup" ]; then
      docker tag "$id" "$backup" || fail "cannot hold $tag's prior image $id under $backup"
      BACKUP_TAGS[${#BACKUP_TAGS[@]} - 1]="$backup"
    fi
    log "snapshot: $tag -> ${id:-<absent>}"
  done < <(managed_tag_list)
}

# Puts every managed tag back the way the snapshot found it. Returns
# nonzero, having reported why, when any tag could not be restored.
restore_tags() {
  local i tag prior backup current failed=0
  for i in "${!MANAGED_TAGS[@]}"; do
    tag="${MANAGED_TAGS[$i]}"
    prior="${PRIOR_IDS[$i]}"
    backup="${BACKUP_TAGS[$i]}"
    if ! current="$(image_id_of "$tag")"; then
      printf '[deploy-no-build-smoke] ERROR: cannot read %s to restore it\n' "$tag" >&2
      failed=1
      continue
    fi
    if [ "$current" != "$prior" ] && [ -n "$current" ] &&
      ! grep -qwF -- "$current" <<<"${OURS_IDS[$i]}"; then
      # The backup tag stays: removing it could delete the prior image,
      # which may now have no other name.
      printf '[deploy-no-build-smoke] ERROR: %s now names %s, which this run never set; another writer changed it, so it is left as is (prior: %s%s)\n' \
        "$tag" "$current" "${prior:-<absent>}" "${backup:+, still held as $backup}" >&2
      failed=1
      continue
    fi
    if [ "$current" != "$prior" ]; then
      if [ -z "$prior" ]; then
        if ! docker image rm "$tag" >/dev/null; then
          printf '[deploy-no-build-smoke] ERROR: cannot remove %s, which this run created\n' "$tag" >&2
          failed=1
          continue
        fi
      elif ! docker tag "$prior" "$tag"; then
        printf '[deploy-no-build-smoke] ERROR: cannot point %s back at %s; its prior image is held as %s\n' \
          "$tag" "$prior" "$backup" >&2
        failed=1
        continue
      fi
    fi
    if [ -n "$backup" ] && ! docker image rm "$backup" >/dev/null; then
      printf '[deploy-no-build-smoke] ERROR: cannot remove the backup tag %s\n' "$backup" >&2
      failed=1
    fi
  done
  return "$failed"
}

# Reads every managed tag back and compares it with the snapshot.
verify_restored_tags() {
  local i tag prior current failed=0
  for i in "${!MANAGED_TAGS[@]}"; do
    tag="${MANAGED_TAGS[$i]}"
    prior="${PRIOR_IDS[$i]}"
    if ! current="$(image_id_of "$tag")"; then
      failed=1
      continue
    fi
    if [ "$current" != "$prior" ]; then
      printf '[deploy-no-build-smoke] ERROR: after cleanup %s names %s, not its prior %s\n' \
        "$tag" "${current:-<absent>}" "${prior:-<absent>}" >&2
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] && log "restored: every managed tag maps as before the smoke"
  return "$failed"
}

# Stops the staged test stack. Returns nonzero, having reported why,
# when `down` fails: its containers may still be running.
stop_test_stack() {
  local out status=0
  [ -f "$STAGE_DIR/docker-compose.deploy.yml" ] || return 0
  out="$(
    cd "$STAGE_DIR" &&
      POSTGRES_PASSWORD=cleanup-only \
        GRAFANA_ADMIN_PASSWORD=cleanup-only \
        "$REAL_DOCKER" compose -p "$COMPOSE_PROJECT" -f docker-compose.deploy.yml down -v --remove-orphans 2>&1
  )" || status=$?
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$out" >&2
    printf '[deploy-no-build-smoke] ERROR: cannot stop the test stack (Compose project %s); its containers and volumes may remain\n' \
      "$COMPOSE_PROJECT" >&2
    return 1
  fi
}

# Stops the test containers, then restores and reads back the tags.
# Idempotent, so the success path and the EXIT trap can both call it.
cleanup() {
  local status=0
  [ "$CLEANED" -eq 0 ] || return 0
  CLEANED=1
  stop_test_stack || status=1
  claim_in_flight_tags || status=1
  if [ "${#MANAGED_TAGS[@]}" -gt 0 ]; then
    restore_tags || status=1
    verify_restored_tags || status=1
  fi
  rm -rf "$STAGE_DIR"
  return "$status"
}

on_exit() {
  local status=$?
  set +e
  if ! cleanup; then
    printf '[deploy-no-build-smoke] ERROR: smoke cleanup failed; see above\n' >&2
    [ "$status" -ne 0 ] || status=1
  fi
  exit "$status"
}

build_bootroot_binary() {
  if [ -x "$BOOTROOT_BIN" ] &&
    "$BOOTROOT_BIN" infra install --help | grep -q -- '--no-build'; then
    return
  fi
  log "building bootroot binary"
  cargo build --bin bootroot
}

reset_existing_stack() {
  log "stopping any existing bootroot compose stack"
  POSTGRES_PASSWORD=cleanup-only \
    GRAFANA_ADMIN_PASSWORD=cleanup-only \
    docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml down -v --remove-orphans \
    >/dev/null 2>&1 || true
  POSTGRES_PASSWORD=cleanup-only \
    GRAFANA_ADMIN_PASSWORD=cleanup-only \
    docker compose -p "$COMPOSE_PROJECT" -f docker-compose.deploy.yml down -v --remove-orphans \
    >/dev/null 2>&1 || true
}

ensure_install_ports_free() {
  local port
  for port in "${OPENBAO_HOST_PORT:-8200}" "${STEPCA_HOST_PORT:-9000}" \
    "${HTTP01_ADMIN_HOST_PORT:-8080}" "${POSTGRES_HOST_PORT:-5433}"; do
    if bash -c ": >/dev/tcp/127.0.0.1/$port" >/dev/null 2>&1; then
      fail "host port 127.0.0.1:$port is already in use; stop the listener first"
    fi
  done
}

prepare_registry_images() {
  local role repository tag digest lookup pinned record id platform digests
  mkdir -p "$ARCHIVE_DIR"
  while IFS=$'\t' read -r role repository tag digest lookup; do
    pinned="$repository@$digest"
    log "pulling $role pin $pinned for $SMOKE_PLATFORM"
    docker pull --platform "$SMOKE_PLATFORM" "$pinned" ||
      fail "pinned image $pinned is not available for $SMOKE_PLATFORM; there is no fallback to the tag $repository:$tag"
    record="$(inspect_selected "$pinned")" ||
      fail "pinned image $pinned has no $SMOKE_PLATFORM image"
    IFS=$'\t' read -r id platform digests <<<"$record"
    [ "$platform" = "$SMOKE_PLATFORM" ] ||
      fail "pinned image $pinned resolved to platform $platform, not $SMOKE_PLATFORM"

    mutating "$lookup" -- docker tag "$pinned" "$lookup"
    # The archive restores the selected platform's image, which a
    # containerd store names by its manifest rather than by the index.
    record_ours "$lookup" "$id"
    SELECTED_ROLES+=("$role")
    SELECTED_IDS+=("$id")

    log "record: dependency=$role pin=$pinned platform=$SMOKE_PLATFORM lookup=$lookup image-id=$id repo-digests=${digests:-<none>}"
    save_selected_platform "$ARCHIVE_DIR/$role.tar" "$lookup"
  done <<<"$PINS"
}

build_responder_image() {
  # `docker-compose.yml` interpolates the responder's `image:` from
  # `BOOTROOT_HTTP01_IMAGE`, and a caller may have exported one, so the
  # build's tag is pinned here rather than left to the environment.
  POSTGRES_PASSWORD=build-only \
    GRAFANA_ADMIN_PASSWORD=build-only \
    BOOTROOT_HTTP01_IMAGE="$RESPONDER_BUILD_TAG" \
    docker compose -f docker-compose.yml build bootroot-http01
}

prepare_responder_image() {
  local base build_tags=("$RESPONDER_BUILD_TAG")
  log "building responder image"
  # The build may pull or refresh its base images before it fails, and
  # a containerd store records those under their tags.
  while IFS= read -r base; do
    [ -z "$base" ] || build_tags+=("$base")
  done < <(awk 'toupper($1) == "FROM" { print $2 }' "$RESPONDER_DOCKERFILE")
  mutating "${build_tags[@]}" -- build_responder_image

  mutating "$RESPONDER_RELEASE_TAG" -- docker tag "$RESPONDER_BUILD_TAG" "$RESPONDER_RELEASE_TAG"
  docker save -o "$ARCHIVE_DIR/http01.tar" "$RESPONDER_RELEASE_TAG"
}

stage_payload() {
  log "staging deploy payload in $STAGE_DIR"
  cp docker-compose.deploy.yml "$STAGE_DIR/"
  mkdir -p "$STAGE_DIR/openbao" "$SHIM_DIR"
  cp openbao/openbao.hcl "$STAGE_DIR/openbao/openbao.hcl"
  cp responder.toml.compose "$STAGE_DIR/responder.toml.compose"

  cat >"$SHIM_DIR/docker" <<EOF
#!/usr/bin/env bash
{
  printf '%q ' "\$@"
  printf '\\n'
} >>"$DOCKER_LOG"
exec "$REAL_DOCKER" "\$@"
EOF
  chmod +x "$SHIM_DIR/docker"
}

run_install() {
  local lookup load_tags=("$RESPONDER_RELEASE_TAG")
  # Loading the archives repoints the lookup tags and the release tag.
  while IFS= read -r lookup; do
    load_tags+=("$lookup")
  done < <(cut -f5 <<<"$PINS")
  mutating "${load_tags[@]}" -- install_staged_payload
}

install_staged_payload() {
  log "running deploy compose install from staged directory"
  (
    cd "$STAGE_DIR"
    PATH="$SHIM_DIR:$PATH" \
      OPENBAO_IMAGE="$(lookup_tag_of openbao)" \
      POSTGRES_IMAGE="$(lookup_tag_of postgres)" \
      BOOTROOT_STEP_CA_IMAGE="$(lookup_tag_of step-ca)" \
      BOOTROOT_HTTP01_IMAGE="$RESPONDER_RELEASE_TAG" \
      "$BOOTROOT_BIN" infra install \
        --compose-file docker-compose.deploy.yml \
        --image-archive-dir "$ARCHIVE_DIR" \
        --no-build
  )
}

assert_no_build_contract() {
  log "verifying docker invocations"
  [ -s "$DOCKER_LOG" ] || fail "docker shim did not record any invocations"

  if grep -Eq '(^| )pull( |$)' "$DOCKER_LOG"; then
    cat "$DOCKER_LOG" >&2
    fail "infra install attempted a pull under --no-build"
  fi

  if grep -Eq '(^| )--build( |$)' "$DOCKER_LOG"; then
    cat "$DOCKER_LOG" >&2
    fail "infra install passed --build under --no-build"
  fi

  local archive
  for archive in openbao postgres step-ca http01; do
    if ! grep -Eq "(^| )load -i .*${archive}\\.tar" "$DOCKER_LOG"; then
      cat "$DOCKER_LOG" >&2
      fail "image archive was not loaded: ${archive}.tar"
    fi
  done

  if ! grep -Eq "compose -f docker-compose\\.deploy\\.yml -p ${COMPOSE_PROJECT} up --no-build --pull never -d openbao postgres step-ca bootroot-http01" "$DOCKER_LOG"; then
    cat "$DOCKER_LOG" >&2
    fail "compose up did not use --no-build --pull never for the default install services"
  fi
}

# The started containers must run exactly the images selected from the
# declared pins, on the same daemon and image store the pins were
# prepared in. RepoDigests are only logged: they need not survive
# save/load, and nothing here depends on them.
assert_running_images() {
  local i role service container running record id platform digests
  [ "${#SELECTED_ROLES[@]}" -gt 0 ] || fail "no declared dependency was prepared"
  for i in "${!SELECTED_ROLES[@]}"; do
    role="${SELECTED_ROLES[$i]}"
    case "$role" in
      openbao | postgres | step-ca) service="$role" ;;
      *) fail "no Compose service is known to run the declared dependency $role" ;;
    esac
    container="$(
      cd "$STAGE_DIR"
      docker compose -p "$COMPOSE_PROJECT" -f docker-compose.deploy.yml ps -q "$service"
    )" || fail "cannot list the $service container"
    [ -n "$container" ] || fail "no $service container is running"
    running="$(docker container inspect --format '{{.Image}}' "$container")" ||
      fail "cannot inspect the $service container"
    [ "$running" = "${SELECTED_IDS[$i]}" ] ||
      fail "$service runs image $running, not the image $role's pin selected: ${SELECTED_IDS[$i]}"

    record="$(inspect_selected "$(lookup_tag_of "$role")")" ||
      fail "cannot inspect the loaded $role image"
    IFS=$'\t' read -r id platform digests <<<"$record"
    [ "$platform" = "$SMOKE_PLATFORM" ] ||
      fail "the loaded $role image is $platform, not $SMOKE_PLATFORM"
    log "running: $service container runs $running ($platform), the selected $role image; loaded image $id repo-digests=${digests:-<none>}"
  done
}

main() {
  require_cmd cargo
  require_cmd docker
  require_cmd python3

  init_smoke
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  reset_existing_stack
  ensure_install_ports_free
  build_bootroot_binary
  snapshot_tags
  prepare_registry_images
  prepare_responder_image
  stage_payload
  run_install
  assert_no_build_contract
  assert_running_images

  cleanup || fail "smoke cleanup failed; see above"
  log "deploy compose no-build smoke passed"
}

main "$@"
