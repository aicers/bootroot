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
  cargo run --bin bootroot -- infra up

  log "Running bootroot init"
  cargo run --bin bootroot -- init --auto-generate \
    --db-dsn "postgres://step:step@127.0.0.1:5432/step"
}

require_cmd cargo
require_cmd docker
run_cli_tests
run_init_scenario
