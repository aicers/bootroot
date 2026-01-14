#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"
}

fail() {
  printf "Error: %s\n" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

run_cli_tests() {
  log "Running CLI unit tests"
  cargo test --bin bootroot

  log "Running CLI integration tests"
  cargo test --test bootroot_cli
}

reset_openbao() {
  log "Resetting OpenBao state"
  docker compose stop openbao >/dev/null 2>&1 || true
  docker rm bootroot-openbao >/dev/null 2>&1 || true
  docker volume rm bootroot_openbao-data >/dev/null 2>&1 || true
}

run_init_scenario() {
  log "Running init scenario"
  reset_openbao

  log "Starting infra"
  if [[ "${BUILD_IMAGES:-0}" == "1" ]]; then
    log "Building local images"
    docker compose build step-ca bootroot-http01
  else
    log "Skipping local image build (set BUILD_IMAGES=1 to enable)"
  fi
  cargo run --bin bootroot -- infra up

  log "Running bootroot init"
  printf "y\ny\ny\nn\n" | cargo run --bin bootroot -- init --auto-generate \
    --db-dsn "postgresql://step:step@127.0.0.1:5432/step" \
    --responder-url "http://localhost:8080"
}

require_cmd cargo
require_cmd docker
run_cli_tests
run_init_scenario
