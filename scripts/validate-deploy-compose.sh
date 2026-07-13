#!/usr/bin/env bash
#
# Validates docker-compose.deploy.yml: the deploy-oriented compose must
# render with `docker compose config` and carry NO `build:` contexts, so a
# prebuilt / air-gapped `infra install` can bring the stack up without a
# source tree. Interpolated image tags fall back to release-built defaults,
# so only the two required secrets need dummy values here.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="docker-compose.deploy.yml"

echo "[validate-deploy-compose] rendering $COMPOSE_FILE"
rendered="$(
  POSTGRES_PASSWORD="validate-only" \
  GRAFANA_ADMIN_PASSWORD="validate-only" \
  docker compose -f "$COMPOSE_FILE" config
)"

if grep -qE '^\s*build:' <<<"$rendered"; then
  echo "[validate-deploy-compose] FAIL: found a build: context in $COMPOSE_FILE" >&2
  grep -nE '^\s*build:' <<<"$rendered" >&2
  exit 1
fi

# The default install services must each resolve to a concrete image tag.
for service in bootroot-openbao bootroot-postgres bootroot-ca bootroot-http01; do
  if ! grep -q "container_name: $service" <<<"$rendered"; then
    echo "[validate-deploy-compose] FAIL: $service missing from rendered config" >&2
    exit 1
  fi
done

echo "[validate-deploy-compose] OK: no build: contexts; default services present"

# Staging smoke: prove the deploy compose resolves from a directory that
# holds ONLY the files a prebuilt payload stages — the compose file plus
# openbao/openbao.hcl and responder.toml.compose — with no source tree
# present. `infra install` itself would create .env, secrets/, and certs/;
# here we pre-create them so `docker compose config` renders cleanly.
STAGE_DIR="$(mktemp -d)"
cleanup() { rm -rf "$STAGE_DIR"; }
trap cleanup EXIT

echo "[validate-deploy-compose] staging smoke in $STAGE_DIR"
cp "$COMPOSE_FILE" "$STAGE_DIR/"
mkdir -p "$STAGE_DIR/openbao" "$STAGE_DIR/secrets" "$STAGE_DIR/certs"
cp openbao/openbao.hcl "$STAGE_DIR/openbao/openbao.hcl"
cp responder.toml.compose "$STAGE_DIR/responder.toml.compose"
cat >"$STAGE_DIR/.env" <<'EOF'
POSTGRES_USER=step
POSTGRES_PASSWORD=validate-only
POSTGRES_DB=stepca
GRAFANA_ADMIN_PASSWORD=validate-only
EOF

(
  cd "$STAGE_DIR"
  docker compose -f "$COMPOSE_FILE" config >/dev/null
)

echo "[validate-deploy-compose] OK: deploy compose resolves from a staged dir with no source tree"
