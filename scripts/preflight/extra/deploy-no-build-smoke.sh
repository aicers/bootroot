#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_VERSION="$(
  awk -F' = ' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' Cargo.toml
)"

OPENBAO_IMAGE="${OPENBAO_IMAGE:-openbao/openbao:2.5.5}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:18.4}"
BOOTROOT_STEP_CA_IMAGE="${BOOTROOT_STEP_CA_IMAGE:-smallstep/step-ca:0.30.2}"
BOOTROOT_HTTP01_IMAGE="${BOOTROOT_HTTP01_IMAGE:-bootroot-http01-responder:$BOOTROOT_VERSION}"

STAGE_DIR="$(mktemp -d)"
ARCHIVE_DIR="$STAGE_DIR/images"
SHIM_DIR="$STAGE_DIR/bin"
DOCKER_LOG="$STAGE_DIR/docker-argv.log"
REAL_DOCKER="$(command -v docker)"

log() {
  printf "[deploy-no-build-smoke] %s\n" "$*"
}

fail() {
  printf "[deploy-no-build-smoke] ERROR: %s\n" "$*" >&2
  exit 1
}

cleanup() {
  if [ -f "$STAGE_DIR/docker-compose.deploy.yml" ]; then
    (
      cd "$STAGE_DIR"
      POSTGRES_PASSWORD=cleanup-only \
        GRAFANA_ADMIN_PASSWORD=cleanup-only \
        "$REAL_DOCKER" compose -f docker-compose.deploy.yml down -v --remove-orphans \
        >/dev/null 2>&1 || true
    )
  fi
  rm -rf "$STAGE_DIR"
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
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
    docker compose -f docker-compose.yml down -v --remove-orphans \
    >/dev/null 2>&1 || true
  POSTGRES_PASSWORD=cleanup-only \
    GRAFANA_ADMIN_PASSWORD=cleanup-only \
    docker compose -f docker-compose.deploy.yml down -v --remove-orphans \
    >/dev/null 2>&1 || true
}

ensure_install_ports_free() {
  local port
  for port in 8200 9000 8080 5433; do
    if bash -c ": >/dev/tcp/127.0.0.1/$port" >/dev/null 2>&1; then
      fail "host port 127.0.0.1:$port is already in use; stop the listener first"
    fi
  done
}

prepare_images() {
  log "pulling third-party images for archive preparation"
  docker pull "$OPENBAO_IMAGE"
  docker pull "$POSTGRES_IMAGE"
  docker pull "$BOOTROOT_STEP_CA_IMAGE"

  log "building responder image"
  POSTGRES_PASSWORD=build-only \
    GRAFANA_ADMIN_PASSWORD=build-only \
    docker compose -f docker-compose.yml build bootroot-http01
  docker tag bootroot-http01-responder:latest "$BOOTROOT_HTTP01_IMAGE"

  mkdir -p "$ARCHIVE_DIR"
  log "saving image archives under $ARCHIVE_DIR"
  docker save -o "$ARCHIVE_DIR/openbao.tar" "$OPENBAO_IMAGE"
  docker save -o "$ARCHIVE_DIR/postgres.tar" "$POSTGRES_IMAGE"
  docker save -o "$ARCHIVE_DIR/step-ca.tar" "$BOOTROOT_STEP_CA_IMAGE"
  docker save -o "$ARCHIVE_DIR/http01.tar" "$BOOTROOT_HTTP01_IMAGE"
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
  log "running deploy compose install from staged directory"
  (
    cd "$STAGE_DIR"
    PATH="$SHIM_DIR:$PATH" \
      OPENBAO_IMAGE="$OPENBAO_IMAGE" \
      POSTGRES_IMAGE="$POSTGRES_IMAGE" \
      BOOTROOT_STEP_CA_IMAGE="$BOOTROOT_STEP_CA_IMAGE" \
      BOOTROOT_HTTP01_IMAGE="$BOOTROOT_HTTP01_IMAGE" \
      "$BOOTROOT_BIN" infra install \
        --compose-file docker-compose.deploy.yml \
        --image-archive-dir "$ARCHIVE_DIR" \
        --no-build
  )
}

assert_no_build_contract() {
  log "verifying docker invocations"
  [ -s "$DOCKER_LOG" ] || fail "docker shim did not record any invocations"

  if grep -Eq '(^| )compose( |.* )pull( |$)' "$DOCKER_LOG"; then
    cat "$DOCKER_LOG" >&2
    fail "infra install attempted docker compose pull under --no-build"
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

  if ! grep -Eq 'compose -f docker-compose\.deploy\.yml up --no-build --pull never -d openbao postgres step-ca bootroot-http01' "$DOCKER_LOG"; then
    cat "$DOCKER_LOG" >&2
    fail "compose up did not use --no-build --pull never for the default install services"
  fi
}

require_cmd cargo
require_cmd docker

reset_existing_stack
ensure_install_ports_free
build_bootroot_binary
prepare_images
stage_payload
run_install
assert_no_build_contract

log "deploy compose no-build smoke passed"
