#!/usr/bin/env bash
#
# Validates that every `container_name:` in the shipped compose files
# follows the install identity, by rendering them through Compose itself.
#
# The Rust-side checks read the compose text and assert the interpolation
# is spelled `${BOOTROOT_INSTANCE:-bootroot}<suffix>`; only Compose can
# say what that text actually renders to. This is what proves the two
# properties the container names carry: the `:-bootroot` default keeps
# the `bootroot-*` literals across scripts/, tests/, docs/ and
# monitoring/ matching, and a recorded instance renames every container
# so two installs can share a host.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Compose interpolates from the invoking environment *and* from the
# project directory's `.env`, which is gitignored and, in any workspace
# where `infra install --instance-name` has run, records that instance.
# Unsetting the process variable alone would therefore still render that
# workspace's names and fail the default-name assertions below. An
# explicit `--env-file` replaces `.env` entirely, so the render depends
# on nothing but this file plus what each case exports. It carries the
# two secrets the compose files require to interpolate at all; both are
# render-only here, nothing is started.
ENV_FILE="$(mktemp)"
trap 'rm -f "$ENV_FILE"' EXIT
cat >"$ENV_FILE" <<'EOF'
POSTGRES_PASSWORD=validate-only
GRAFANA_ADMIN_PASSWORD=validate-only
EOF
# The profiles the seven services are spread across: without them
# `config` omits prometheus and the two grafana services.
PROFILES=(--profile lan --profile public)

SUFFIXES=(
  -openbao
  -postgres
  -ca
  -http01
  -prometheus
  -grafana
  -grafana-public
)

# Renders one compose file set under an instance name ("" for unset) and
# asserts every container is named after it.
check_render() {
  local instance="$1"
  shift
  local expected_prefix="${instance:-bootroot}"
  local label="${instance:-<unset>}"
  local rendered

  echo "[validate-compose-instance-names] rendering $* with BOOTROOT_INSTANCE=$label"
  # The process environment outranks the env file, so exporting the
  # instance here still wins for the non-default cases, while `env -u`
  # plus an env file that never mentions the variable is what makes the
  # "unset" case genuinely unset.
  if [ -n "$instance" ]; then
    rendered="$(BOOTROOT_INSTANCE="$instance" \
      docker compose --env-file "$ENV_FILE" "${PROFILES[@]}" "$@" config)"
  else
    rendered="$(env -u BOOTROOT_INSTANCE \
      docker compose --env-file "$ENV_FILE" "${PROFILES[@]}" "$@" config)"
  fi

  local suffix
  for suffix in "${SUFFIXES[@]}"; do
    if ! grep -q "container_name: ${expected_prefix}${suffix}\$" <<<"$rendered"; then
      echo "[validate-compose-instance-names] FAIL: ${expected_prefix}${suffix} missing from rendered $*" >&2
      grep -n 'container_name:' <<<"$rendered" >&2
      exit 1
    fi
  done

  # A non-default instance must leave no default-named container behind:
  # a literal that escaped the interpolation would collide with a
  # co-located default install, which is the collision this all exists
  # to remove.
  if [ -n "$instance" ] && [ "$instance" != "bootroot" ]; then
    if grep -qE '^\s*container_name: bootroot-' <<<"$rendered"; then
      echo "[validate-compose-instance-names] FAIL: a bootroot-* container survived instance $instance" >&2
      grep -nE '^\s*container_name: bootroot-' <<<"$rendered" >&2
      exit 1
    fi
  fi
}

# The overlay layered as a second `-f` over docker-compose.yml adds
# network aliases only; a `container_name:` here would bypass the
# derivation entirely, so it renders as part of the combination below
# and is checked for its own absence.
if grep -qE '^\s*container_name:' docker-compose.test.yml; then
  echo "[validate-compose-instance-names] FAIL: docker-compose.test.yml must declare no container_name:" >&2
  exit 1
fi

check_render "" -f docker-compose.yml -f docker-compose.test.yml
check_render "insight" -f docker-compose.yml -f docker-compose.test.yml
check_render "" -f docker-compose.deploy.yml
check_render "insight" -f docker-compose.deploy.yml

echo "[validate-compose-instance-names] OK: every container name follows the instance identity"
