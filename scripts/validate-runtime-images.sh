#!/usr/bin/env bash
#
# Validates deploy/runtime-images.json, the committed declaration of the
# exact upstream registry images this revision of bootroot approves as
# runtime dependencies of its default production stack.
#
# First the real declaration is checked against both Compose files:
# schema-1 format, and every default active service's image against the
# declared repository and tag, with no declaration missing or extra. The
# checks live in scripts/runtime_images.py; each Compose file is rendered
# with `docker compose config --format json` under an explicit env file
# and a scrubbed environment, so neither the checkout's `.env` nor an
# installer image override in the caller's environment stands in for the
# source default.
#
# Then the checker itself is exercised against fixtures: one positive or
# negative case per rule, so a rule that silently stopped firing turns
# this script red instead of leaving the real check vacuously green.
#
# Rust-side references (the OpenBao Agent sidecar image, the step-ca
# helper image) are checked by `cargo test`, which reads the same
# declaration with `include_str!`.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LABEL="validate-runtime-images"
DECLARATION="deploy/runtime-images.json"
CHECKER="scripts/runtime_images.py"
COMPOSE_FILES=(docker-compose.yml docker-compose.deploy.yml)
REAL_SETS=()
for file in "${COMPOSE_FILES[@]}"; do
  REAL_SETS+=(--compose-set "$file")
done

PYTHON="${PYTHON:-python3}"

die() {
  echo "[$LABEL] FAIL: $1" >&2
  exit 1
}

ok() {
  echo "[$LABEL] ok: $1"
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

run_checker() {
  "$PYTHON" "$CHECKER" "$@"
}

# ---------------------------------------------------------------------------
# The committed declaration against the committed sources
# ---------------------------------------------------------------------------

echo "[$LABEL] checking $DECLARATION against ${COMPOSE_FILES[*]}"
CLEAN_OUTPUT="$(run_checker --declaration "$DECLARATION" check "${REAL_SETS[@]}")" ||
  die "the committed declaration does not match the committed sources"
printf '%s\n' "$CLEAN_OUTPUT"

# ---------------------------------------------------------------------------
# Image references outside Compose and Rust
# ---------------------------------------------------------------------------
#
# `test-core` pre-pulls the OpenBao image its real-daemon TLS test runs
# (whose constant `cargo test` holds to the declaration), so the pull
# must name that image too. The deploy no-build smoke reads its images
# from the declaration itself and carries no literal to check.
CI_WORKFLOW=".github/workflows/ci.yml"
PREPULLS="$(sed -n 's/^ *run: docker pull \([^ ]*\) *$/\1/p' "$CI_WORKFLOW")"
OPENBAO_PREPULL="$(grep -E '(^|/)openbao/openbao[:@]' <<<"$PREPULLS" || true)"
[ "$(grep -c . <<<"$OPENBAO_PREPULL")" -eq 1 ] ||
  die "expected exactly one OpenBao pre-pull in $CI_WORKFLOW, found: ${PREPULLS:-none}"
run_checker --declaration "$DECLARATION" reference \
  --source "$CI_WORKFLOW OpenBao pre-pull" openbao "$OPENBAO_PREPULL" ||
  die "$CI_WORKFLOW pre-pulls an OpenBao image other than the declared one"

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

LAST_OUTPUT=""

# expect_pass <case> <checker args...>
expect_pass() {
  local name="$1"
  shift
  if ! LAST_OUTPUT="$(run_checker "$@" 2>&1)"; then
    printf '%s\n' "$LAST_OUTPUT" >&2
    die "$name: expected the checker to accept, it rejected"
  fi
  ok "$name"
}

# expect_fail <case> <expected message fragment> <checker args...>
#
# A rejection must be a finding (exit 1) carrying the expected message.
# A tool error (exit 2) or a finding about something else means the case
# did not exercise the rule it names.
expect_fail() {
  local name="$1" fragment="$2" status=0
  shift 2
  LAST_OUTPUT="$(run_checker "$@" 2>&1)" || status=$?
  if [ "$status" -ne 1 ]; then
    printf '%s\n' "$LAST_OUTPUT" >&2
    die "$name: expected a validation failure (exit 1), got exit $status"
  fi
  if ! grep -qF -- "$fragment" <<<"$LAST_OUTPUT"; then
    printf '%s\n' "$LAST_OUTPUT" >&2
    die "$name: rejection did not mention: $fragment"
  fi
  ok "$name"
}

# mutate <output> <python statements over `d`, the parsed declaration>
mutate() {
  local out="$WORK_DIR/$1"
  "$PYTHON" - "$DECLARATION" "$out" "$2" <<'EOF'
import json
import sys

source, target, statements = sys.argv[1], sys.argv[2], sys.argv[3]
with open(source, encoding="utf-8") as handle:
    d = json.load(handle)
by_role = {entry["dependency"]: entry for entry in d["dependencies"]}
exec(statements)
with open(target, "w", encoding="utf-8") as handle:
    json.dump(d, handle, indent=2)
EOF
  printf '%s' "$out"
}

# override <name> <compose YAML> — writes a Compose override fixture.
override() {
  local out="$WORK_DIR/$1.yml"
  printf '%s\n' "$2" >"$out"
  printf '%s' "$out"
}

DEPLOY="docker-compose.deploy.yml"
SOURCE="docker-compose.yml"
OTHER_DIGEST="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

# Caller image overrides and Compose selection variables must not reach
# the render: the result equals the clean run's.
ENV_OUTPUT="$(
  OPENBAO_IMAGE=openbao/openbao:9.9.9 \
    POSTGRES_IMAGE=postgres:99 \
    BOOTROOT_STEP_CA_IMAGE=smallstep/step-ca:9.9.9 \
    BOOTROOT_HTTP01_IMAGE=example.invalid/other:1 \
    PROMETHEUS_IMAGE=prom/prometheus:v0 \
    GRAFANA_IMAGE=grafana/grafana:0 \
    COMPOSE_PROFILES=lan,public \
    COMPOSE_FILE=/nonexistent/compose.yml \
    run_checker --declaration "$DECLARATION" check "${REAL_SETS[@]}"
)" || die "caller image overrides changed the source-default validation result"
[ "$ENV_OUTPUT" = "$CLEAN_OUTPUT" ] ||
  die "caller image overrides changed the output: $ENV_OUTPUT"
ok "caller environment overrides do not contaminate source defaults"

# A conflicting `.env` beside the compose file must not either.
DOTENV_DIR="$WORK_DIR/dotenv"
mkdir -p "$DOTENV_DIR"
cp "$DEPLOY" "$DOTENV_DIR/$DEPLOY"
cat >"$DOTENV_DIR/.env" <<'EOF'
POSTGRES_IMAGE=postgres:99
OPENBAO_IMAGE=openbao/openbao:9.9.9
BOOTROOT_STEP_CA_IMAGE=smallstep/step-ca:9.9.9
COMPOSE_PROFILES=lan,public
POSTGRES_PASSWORD=from-dotenv
GRAFANA_ADMIN_PASSWORD=from-dotenv
EOF
expect_pass "a conflicting .env is isolated" \
  --declaration "$DECLARATION" check --compose-set "$DOTENV_DIR/$DEPLOY"

# The monitoring services and the product-built responder are in the
# rendered model; the default check above already accepts them as
# classified. Confirm the render really carried them, so the positive
# result is not vacuous.
MODEL="$(
  env -u COMPOSE_PROFILES -u COMPOSE_FILE docker compose \
    --env-file "$DOTENV_DIR/.env" --profile '*' -f "$DEPLOY" config --services
)"
for service in prometheus grafana grafana-public bootroot-http01 openbao postgres step-ca; do
  grep -qx "$service" <<<"$MODEL" || die "rendered model is missing $service"
done
ok "rendered model carries monitoring and responder services"

SIDECARS="$(override sidecars '
services:
  openbao-agent-stepca:
    image: openbao/openbao:2.5.5
    command: ["agent", "-config=/dev/null"]
  openbao-agent-responder:
    image: openbao/openbao:2.5.5
    command: ["agent", "-config=/dev/null"]')"
expect_pass "generated OpenBao Agent sidecars run the declared image" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$SIDECARS"

QUALIFIED="$(override qualified '
services:
  postgres:
    image: docker.io/library/postgres:18.4
  openbao:
    image: index.docker.io/openbao/openbao:2.5.5')"
expect_pass "Docker Hub shorthand and qualified spellings are one repository" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$QUALIFIED"

PINNED="$(override pinned "
services:
  postgres:
    image: postgres:18.4@$(run_checker --declaration "$DECLARATION" pins |
  awk -F'\t' '$1 == "postgres" { print $4 }')")"
expect_pass "a source reference carrying the declared digest is accepted" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$PINNED"

# A same-tag rebuild changes only the digest; the Compose tag defaults
# stay. The format check accepts it (which is not compatibility approval).
DIGEST_ONLY="$(mutate digest-only.json "by_role['postgres']['digest'] = '$OTHER_DIGEST'")"
expect_pass "a digest-only change needs no Compose change" \
  --declaration "$DIGEST_ONLY" check "${REAL_SETS[@]}"

NULL_VERSION="$(mutate null-version.json "by_role['step-ca']['version'] = None")"
expect_pass "an explicit null version is accepted" \
  --declaration "$NULL_VERSION" check --compose-set "$DEPLOY"

# ---------------------------------------------------------------------------
# Negative cases: declaration format
# ---------------------------------------------------------------------------

fail_declaration() {
  local name="$1" fragment="$2" statements="$3" file
  file="$(mutate "neg-$RANDOM-$RANDOM.json" "$statements")"
  expect_fail "$name" "$fragment" --declaration "$file" pins
}

fail_declaration "unsupported schema" "unsupported schema 2" "d['schema'] = 2"
fail_declaration "schema as a string" "unsupported schema '1'" "d['schema'] = '1'"
fail_declaration "schema as a boolean" "unsupported schema True" "d['schema'] = True"
fail_declaration "missing schema" "missing top-level field: schema" "del d['schema']"
fail_declaration "unknown top-level field" "unknown top-level fields: profiles" \
  "d['profiles'] = ['lan']"
fail_declaration "unknown entry field" "unknown fields: profile" \
  "by_role['openbao']['profile'] = 'default'"
fail_declaration "duplicate role" "'postgres' is declared more than once" \
  "d['dependencies'].append(dict(by_role['postgres']))"
fail_declaration "duplicate platform" "lists 'linux/amd64' more than once" \
  "by_role['openbao']['platforms'] = ['linux/amd64', 'linux/amd64']"
fail_declaration "empty role" "dependency '' must be a lowercase" \
  "by_role['openbao']['dependency'] = ''"
fail_declaration "path role" "dependency '../openbao' must be a lowercase" \
  "by_role['openbao']['dependency'] = '../openbao'"
fail_declaration "uppercase role" "dependency 'OpenBao' must be a lowercase" \
  "by_role['openbao']['dependency'] = 'OpenBao'"
fail_declaration "placeholder role" "dependency 'todo' is a placeholder" \
  "by_role['openbao']['dependency'] = 'todo'"
fail_declaration "angle-bracket placeholder role" "dependency '<dependency>' must be" \
  "by_role['openbao']['dependency'] = '<dependency>'"
fail_declaration "missing digest" "is missing fields: digest" "del by_role['postgres']['digest']"
fail_declaration "uppercase digest" "must be 'sha256:' followed by 64 lowercase hex" \
  "by_role['postgres']['digest'] = by_role['postgres']['digest'].upper()"
fail_declaration "short digest" "must be 'sha256:' followed by 64 lowercase hex" \
  "by_role['postgres']['digest'] = 'sha256:32ca0af8'"
fail_declaration "placeholder digest" "is a placeholder" \
  "by_role['postgres']['digest'] = 'sha256:' + 'd' * 64"
fail_declaration "missing version" "is missing fields: version" "del by_role['postgres']['version']"
fail_declaration "non-SemVer version" "version '18.4' must be a canonical SemVer" \
  "by_role['postgres']['version'] = '18.4'"
fail_declaration "version disagreeing with a numeric tag" "its comparison version is '18.4.0'" \
  "by_role['postgres']['version'] = '18.5.0'"
fail_declaration "missing platforms" "is missing fields: platforms" \
  "del by_role['step-ca']['platforms']"
fail_declaration "empty platforms" "platforms must be a nonempty list" \
  "by_role['step-ca']['platforms'] = []"
fail_declaration "unknown platform spelling" "unsupported platform 'linux/arm64'" \
  "by_role['step-ca']['platforms'] = ['linux/amd64', 'linux/arm64']"
fail_declaration "selected platform absent" "does not include the selected platform" \
  "by_role['step-ca']['platforms'] = ['linux/arm64/v8']"
fail_declaration "repository without a registry" "must name its registry explicitly" \
  "by_role['postgres']['repository'] = 'postgres'"
fail_declaration "non-canonical Docker Hub repository" "use 'docker.io/library/postgres'" \
  "by_role['postgres']['repository'] = 'docker.io/postgres'"
fail_declaration "repository carrying a tag" "invalid path component 'postgres:18.4'" \
  "by_role['postgres']['repository'] = 'docker.io/library/postgres:18.4'"
fail_declaration "tag-only declaration" "is missing fields: digest, platforms" \
  "d['dependencies'] = [{k: e[k] for k in ('dependency', 'repository', 'tag', 'version')} for e in d['dependencies']]"

DUPLICATE_KEY="$WORK_DIR/duplicate-key.json"
sed 's/"schema": 1,/"schema": 1, "schema": 1,/' "$DECLARATION" >"$DUPLICATE_KEY"
expect_fail "duplicate JSON key" "duplicate JSON key 'schema'" --declaration "$DUPLICATE_KEY" pins

expect_fail "unsupported selected platform" "does not include the selected platform 'linux/arm64/v8'" \
  --declaration "$DECLARATION" --platform linux/arm64/v8 pins
expect_fail "unknown selected platform" "unsupported selected platform 'darwin/arm64'" \
  --declaration "$DECLARATION" --platform darwin/arm64 pins

# ---------------------------------------------------------------------------
# Negative cases: declaration coverage and source consistency
# ---------------------------------------------------------------------------

MISSING="$(mutate missing.json \
  "d['dependencies'] = [e for e in d['dependencies'] if e['dependency'] != 'step-ca']")"
expect_fail "missing declaration" "runs role 'step-ca', which is not declared" \
  --declaration "$MISSING" check --compose-set "$SOURCE"

EXTRA="$(mutate extra.json "d['dependencies'].append({
  'dependency': 'debian', 'repository': 'docker.io/library/debian',
  'tag': 'bookworm-slim', 'version': None, 'digest': '$OTHER_DIGEST',
  'platforms': ['linux/amd64']})")"
expect_fail "extra declaration (build-only base)" "declared dependency 'debian' is not run" \
  --declaration "$EXTRA" check --compose-set "$DEPLOY"

MONITORING="$(mutate monitoring.json "d['dependencies'].append({
  'dependency': 'prometheus', 'repository': 'docker.io/prom/prometheus',
  'tag': 'v3.13.1', 'version': '3.13.1', 'digest': '$OTHER_DIGEST',
  'platforms': ['linux/amd64']})")"
expect_fail "monitoring extra declaration" "declared dependency 'prometheus' is not run" \
  --declaration "$MONITORING" check --compose-set "$DEPLOY"

PRODUCT="$(mutate product.json "d['dependencies'].append({
  'dependency': 'bootroot-http01', 'repository': 'docker.io/library/bootroot-http01-responder',
  'tag': '0.3.0', 'version': '0.3.0', 'digest': '$OTHER_DIGEST',
  'platforms': ['linux/amd64']})")"
expect_fail "product-built image declared" "declared dependency 'bootroot-http01' is not run" \
  --declaration "$PRODUCT" check --compose-set "$DEPLOY"

TAG_ONLY_CHANGE="$(mutate tag-change.json \
  "by_role['postgres']['tag'] = '18.5'; by_role['postgres']['version'] = '18.5.0'")"
expect_fail "tag change not mirrored by Compose" "tag '18.4' does not match declared '18.5'" \
  --declaration "$TAG_ONLY_CHANGE" check "${REAL_SETS[@]}"

ADDED="$(override added '
services:
  cache:
    image: redis:7.4')"
expect_fail "caller-added undeclared active service" "unclassified service 'cache'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$ADDED"

ADDED_DECLARED_IMAGE="$(override added-declared-image '
services:
  postgres-replica:
    image: postgres:18.4')"
expect_fail "caller-added service reusing a declared image" \
  "unclassified service 'postgres-replica'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$ADDED_DECLARED_IMAGE"

ADDED_GATED="$(override added-gated '
services:
  exporter:
    image: prom/node-exporter:v1.9.1
    profiles: [lan]')"
expect_fail "caller-added profile-gated service" "unclassified service 'exporter'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$ADDED_GATED"

ACTIVATED="$(override activated '
services:
  prometheus:
    profiles: !reset []')"
expect_fail "activated monitoring service" "excluded monitoring service 'prometheus' is active" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$ACTIVATED"

UNKNOWN_PROFILE="$(override unknown-profile '
services:
  grafana:
    profiles: !override [ops]')"
expect_fail "unknown profile in the model" "'grafana' uses unknown profiles: ops" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$UNKNOWN_PROFILE"

GATED_ROLE="$(override gated-role '
services:
  postgres:
    profiles: [lan]')"
expect_fail "declared role moved behind a profile" "declared dependency 'postgres' is not run" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$GATED_ROLE"

expect_fail "unsupported profile selection" "unsupported profile selection 'lan'" \
  --declaration "$DECLARATION" check --profile lan --compose-set "$DEPLOY"
expect_fail "unknown profile selection" "unknown profile selection 'ops'" \
  --declaration "$DECLARATION" check --profile ops --compose-set "$DEPLOY"

WRONG_TAG="$(override wrong-tag '
services:
  postgres:
    image: postgres:99')"
expect_fail "explicit override changing the image tag" "tag '99' does not match declared '18.4'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$WRONG_TAG"

WRONG_REPOSITORY="$(override wrong-repository '
services:
  postgres:
    image: bitnami/postgresql:18.4')"
expect_fail "mismatched repository" \
  "repository 'docker.io/bitnami/postgresql' does not match declared 'docker.io/library/postgres'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$WRONG_REPOSITORY"

MIRROR="$(override mirror '
services:
  openbao:
    image: registry.example.com/openbao/openbao:2.5.5')"
expect_fail "dotted registry host is not a Docker Hub namespace" \
  "repository 'registry.example.com/openbao/openbao' does not match" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$MIRROR"

LOCAL_REGISTRY="$(override local-registry '
services:
  step-ca:
    image: localhost:5000/smallstep/step-ca:0.30.2')"
expect_fail "registry host with a port is not a Docker Hub namespace" \
  "repository 'localhost:5000/smallstep/step-ca' does not match" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$LOCAL_REGISTRY"

LOCALHOST="$(override localhost '
services:
  step-ca:
    image: localhost/smallstep/step-ca:0.30.2')"
expect_fail "localhost is not a Docker Hub namespace" \
  "repository 'localhost/smallstep/step-ca' does not match" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$LOCALHOST"

WRONG_DIGEST="$(override wrong-digest "
services:
  postgres:
    image: postgres:18.4@$OTHER_DIGEST")"
expect_fail "source reference pinning another digest" "does not match declared sha256:" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$WRONG_DIGEST"

SIDECAR_DRIFT="$(override sidecar-drift '
services:
  openbao-agent-stepca:
    image: openbao/openbao:2.5.4
    command: ["agent", "-config=/dev/null"]')"
expect_fail "OpenBao Agent sidecar drift" \
  "'openbao-agent-stepca' image 'openbao/openbao:2.5.4': tag '2.5.4'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$SIDECAR_DRIFT"

RENAMED_RESPONDER="$(override renamed-responder '
services:
  bootroot-http01:
    image: ghcr.io/aicers/bootroot-http01-responder:0.3.0')"
expect_fail "product-built responder renamed" \
  "must keep the repository 'bootroot-http01-responder'" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$RENAMED_RESPONDER"

# A fixture interpolating an image variable the checker has never heard
# of: its default is what gets validated, whatever the caller exports.
# shellcheck disable=SC2016 # the `${...}` is Compose interpolation, not shell
CUSTOM_VARIABLE="$(override custom-variable '
services:
  postgres:
    image: ${CUSTOM_POSTGRES_IMAGE:-postgres:18.4}')"
CUSTOM_POSTGRES_IMAGE=postgres:99 expect_pass "fixture image variables are cleared too" \
  --declaration "$DECLARATION" check --compose-set "$DEPLOY" "$CUSTOM_VARIABLE"

expect_fail "a pre-pull of another tag" "tag '2.5.4' does not match declared '2.5.5'" \
  --declaration "$DECLARATION" reference --source fixture openbao openbao/openbao:2.5.4

echo "[$LABEL] OK: declaration valid, sources consistent, all fixture cases behave"
