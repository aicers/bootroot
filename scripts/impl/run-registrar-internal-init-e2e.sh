#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E for `bootroot init` on an endpoint-enabled loopback
# host (#766).
#
# `run-registrar-internal-e2e.sh` proves the `auth/cert` contract against
# a bare OpenBao: what the entry accepts, and what the minted token may
# do.  It says nothing about how the credential gets there.  This
# scenario covers the other half — the acceptance criterion that an
# endpoint-enabled *loopback* host completes `init` with a
# TLS-terminated `:8200`, an `https://` state URL, and a certificate
# login that works — and it needs a whole deployment to do it: step-ca
# has to sign the internal leaf through the ordinary outbound ACME path,
# and the HTTP-01 responder has to answer the challenge for it.
#
# Three things here are only observable end to end, and each one is a
# way this could be wrong while every unit test passed:
#
#   - step-ca resolves an HTTP-01 identifier through the responder's
#     Docker network aliases.  The internal identity has no
#     `ServiceEntry`, so it is not in the set `service add` maintains,
#     and without an alias of its own the challenge cannot resolve at
#     all.
#   - `init` issues the internal leaf through this install's *own*
#     published step-ca and responder ports.  On the compose defaults a
#     hard-coded `:9000`/`:8080` is indistinguishable from a derived
#     one; on moved ports it reaches nothing, and on a host that already
#     has an install it reaches the other one.
#   - the listener transition, the recorded URL and the certificate
#     login are one sequence.  Each is assertable alone and only their
#     composition is the criterion.
#
# So the ports are moved deliberately.  This scenario allocates four
# free ones and installs under a run-scoped instance name into a
# temporary directory, on the `run-two-instance-isolation.sh` model: it
# is safe on a host that already carries a default `bootroot` install,
# and it is the arrangement that exercises the derivation.
#
# The endpoint-*disabled* half of the criterion is not re-tested here.
# Every other lifecycle arm is an endpoint-disabled host — none of them
# records the predicate — and each drives its whole run over the
# plaintext `http://` URL `init` recorded, so a listener that
# transitioned when it should not have would fail them outright.
#
# The predicate is seeded into `state.json` by hand between `install`
# and `init`.  Defining and writing it belongs to the registrar endpoint
# work; `init` only consumes it, and consuming it is what is under test.
#
# `init` itself runs as root here (#880).  The five protected artifacts
# below the internal directory are published uid 0 / gid 0, and a
# process that cannot establish that ownership publishes none of them,
# so an endpoint-enabled `init` is a privileged command and this
# scenario is the only place that is observable end to end.  Everything
# else still runs as the invoking user; the reads that touch the
# root-owned `0700` internal directory go through `sudo -n` one call at
# a time rather than the whole run being elevated.  Passwordless sudo is
# therefore a prerequisite, and a machine without it cannot run this
# scenario at all — `ensure_prerequisites` says so rather than letting
# `init` fail with a permission error two minutes in.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# A `COMPOSE_PROJECT_NAME` or `BOOTROOT_INSTANCE` inherited from the
# invoking shell outranks the recorded instance name and would point
# this run at whatever that names.  The host-port variables would
# likewise override the ones allocated below, collapsing the run onto a
# co-located install's ports.
unset COMPOSE_PROJECT_NAME BOOTROOT_INSTANCE
unset OPENBAO_HOST_PORT POSTGRES_HOST_PORT STEPCA_HOST_PORT HTTP01_ADMIN_HOST_PORT
unset POSTGRES_HOST POSTGRES_PORT POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB

# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"
# shellcheck source=lib/ports.sh
. "$SCRIPT_DIR/lib/ports.sh"
# shellcheck source=lib/audit-log.sh
. "$SCRIPT_DIR/lib/audit-log.sh"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)-$$}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/registrar-internal-init-${RUN_ID}}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"

BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
COMPOSE_FILE_NAME="docker-compose.deploy.yml"

RUN_TOKEN="${RUN_TOKEN:-${GITHUB_RUN_ID:-$(date +%s)$$}}"
RUN_TOKEN="$(printf '%s' "$RUN_TOKEN" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
INSTANCE="regint-${RUN_TOKEN}"
# `MAX_INSTANCE_NAME_LEN` in src/commands/compose_project.rs.
MAX_INSTANCE_NAME_LEN=39

# The `bootroot-http01` image the deploy compose file references.  A
# run-scoped tag so the build cannot overwrite an image a co-located
# install is running; removed again on the way out.
HTTP01_IMAGE="${HTTP01_IMAGE:-bootroot-http01-responder:registrar-internal-${RUN_TOKEN}}"
export BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE"
HTTP01_IMAGE_BUILT=0

# The identity the predicate composes.  The SAN below is what the
# `auth/cert` entry allows and what step-ca must resolve; it is spelled
# out rather than derived so a change to the composition fails here.
DOMAIN="trusted.domain"
HOST_LABEL="bootroot-01"
INTERNAL_SAN="001.bootroot-registrar-internal.${HOST_LABEL}.${DOMAIN}"
INTERNAL_ENTRY="bootroot-registrar-internal"

INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-60}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-2}"

CURRENT_PHASE="startup"
CURL_BIN=""
PYTHON_BIN=""
RUN_ROOT=""
WORK_DIR=""
SECRETS_DIR=""
INTERNAL_DIR=""
PORT_POSTGRES=0
PORT_OPENBAO=0
PORT_STEPCA=0
PORT_HTTP01=0
# The shared audit store this run provisions, and the operator
# configuration file that is its only definition.
AUDIT_STORE_BASE=""
AUDIT_STORE_DIR=""
AGENT_CONFIG_FILE=""
# What the `filesystem`-mode activation below put on the host, so that
# cleanup can take it back off whether the run reached the end or a
# `fail` in the middle of it.  A mount left behind outlives this run,
# and the `rm -rf` that removes the store base would descend into it.
RESERVE_STORE_DIR=""
RESERVE_IMAGE=""
RESERVE_UNIT_NAME=""
# Where the reserve runs below point `bootroot init` so that one which
# gets *past* the audit store stops immediately afterwards.
#
# The audit store is provisioned before any Docker call, and a run that
# reaches `enforced` carries straight on into `bootstrap_openbao` --
# which would initialise this scenario's OpenBao, without saving its
# unseal keys, well before `run_init` gets to.  The next step after the
# outcome that does reach the network is the OpenBao health check, so a
# URL nothing answers on ends the run there: `--agent-config` has
# already been read and the outcome already printed, and nothing of the
# deployment has been touched.  A non-default `--openbao-url` is left
# alone by the port resolution, which is what makes this reliable.
RESERVE_DEAD_OPENBAO_URL="http://127.0.0.1:1"
# The container path `openbao/openbao.hcl` writes its file audit device
# to.  Unchanged by the override this run renders — only what backs it
# moves.
OPENBAO_AUDIT_CONTAINER_DIR="/openbao/audit"
OPENBAO_AUDIT_CONTAINER_LOG="${OPENBAO_AUDIT_CONTAINER_DIR}/audit.log"
# `init`'s machine-readable summary, and the root token read out of it.
# Parsed rather than scraped from the human summary so the read does not
# depend on which locale the run happened to print in.
#
# Deliberately under `RUN_ROOT` rather than `ARTIFACT_DIR`, and set in
# `create_run_root` once that directory exists.  A root-run `init`
# writes this file as root at mode `0600`, and it carries the root
# token, the unseal keys, the step-ca password and every AppRole
# `secret_id` this run minted.  In the artifact directory it would be a
# credential bundle published by the CI upload — beside an `init.log`
# this harness redacts the root token out of for exactly that reason —
# and a root-owned file the invoking user can neither read nor remove
# afterwards.  `RUN_ROOT` already holds the run's secrets tree at
# `0700`, and its removal already copes with root-owned content.
INIT_SUMMARY_JSON=""
# The root token, staged out of that summary into two root-owned `0600`
# files: the token on its own for the rotation test, and a `curl`
# configuration file carrying it as an `X-Vault-Token` header.
#
# Files rather than a shell variable because every use of the token is
# elevated, and a value handed to an elevated command becomes an
# argument of it.  `ps` shows every process's arguments to every user on
# the host, so `curl -H "X-Vault-Token: ..."` publishes the token for as
# long as the request runs, and `sudo env NAME=<token> ...` publishes it
# for as long as the test does.  A path published that way discloses
# nothing: the files are readable by root alone, and both live under
# `RUN_ROOT`, whose removal already copes with root-owned content.
OPENBAO_ROOT_TOKEN_FILE=""
OPENBAO_CURL_CONFIG=""
# The library test binary the device's rotation runs through.  Built as
# the invoking user and executed under `sudo -n`, so no `cargo`
# invocation ever runs as root and nothing under `target/` changes
# owner.
ROTATION_TEST_BIN=""
# How long the two entries the shared file-audit assertion looks for are
# given to reach a device whose bind source has just moved.  The
# bring-up returns once the containers are up, not once the two infra
# sidecars have logged in and rendered, so the assertion needs a window
# rather than a single probe.
AUDIT_ENTRIES_ATTEMPTS="${AUDIT_ENTRIES_ATTEMPTS:-60}"
AUDIT_ENTRIES_DELAY_SECS="${AUDIT_ENTRIES_DELAY_SECS:-2}"

log_phase() {
  CURRENT_PHASE="$1"
  printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"
  printf '[registrar-internal-init][%s]\n' "$1" | tee -a "$RUN_LOG"
}

log() {
  printf '[registrar-internal-init][%s] %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

# Reports each assertion individually, so a passing run reads as a
# checklist rather than as silence.
pass() {
  printf '[registrar-internal-init][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

fail() {
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true
  echo "[registrar-internal-init][${CURRENT_PHASE}] FAIL $1" >&2
  exit 1
}

assert_equal() {
  local what="$1" expected="$2" actual="$3"
  [ "$expected" = "$actual" ] || fail "${what}: expected '${expected}', got '${actual}'"
  pass "$what"
}

# The same, for a lower bound rather than an equality.
#
# A `yes`/`no` rendered by the caller would compare correctly and then
# throw away the two numbers that say *how* it failed, which is the one
# thing the log is read for afterwards.  Both figures are reported here
# instead.
assert_at_least() {
  local what="$1" floor="$2" actual="$3"
  [ "$actual" -ge "$floor" ] ||
    fail "${what}: expected at least '${floor}', got '${actual}'"
  pass "$what"
}

# uid, gid and mode of a file below the root-owned internal directory,
# in one probe.  GNU and BSD `stat` spell the format differently and
# both are tried, as the mode probe this replaces did.
file_owner_mode() {
  sudo -n stat -c '%u:%g:%a' "$1" 2>/dev/null || sudo -n stat -f '%u:%g:%OLp' "$1"
}

# The image's identity as a file and as a filesystem, in one probe.
#
# Read while the reserve is mounted, so every term has to be one the
# mounted filesystem does not move on its own; see the caller for which
# ones do.
image_identity() {
  printf '%s %s\n' \
    "$(sudo -n stat -c '%i %s' "$1")" \
    "$(sudo -n blkid -o value -s UUID "$1")"
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  # The certificate login below presents a PEM client certificate.  The
  # system curl cannot always do that (macOS ships a SecureTransport
  # build that wants a keychain identity), so the login goes through
  # python3's `ssl`, which takes the PEM pair directly on every platform
  # this runs on.
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  # Resolved here and invoked by absolute path under `sudo`: sudo's
  # `secure_path` is not this shell's `PATH`, and a python3 or curl from
  # a package manager prefix is exactly what it drops.
  CURL_BIN="$(command -v curl)"
  PYTHON_BIN="$(command -v python3)"
  # Endpoint-enabled `init` publishes the five protected artifacts uid 0
  # / gid 0 and refuses to publish any of them otherwise, so this
  # scenario cannot run unprivileged.  Probed before anything is
  # installed: a prompt-free failure now beats a permission error after
  # a deployment has been brought up, and `sudo -n` is what keeps this
  # from blocking on a password nobody is there to type.
  sudo -n true >/dev/null 2>&1 ||
    fail "passwordless sudo is required: endpoint-enabled 'bootroot init' publishes the \
bootroot-internal credential as root, and this scenario runs it through 'sudo -n'"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -n "$RUN_TOKEN" ] || fail "RUN_TOKEN reduced to the empty string; supply a token of [a-z0-9]"
  [ "${#INSTANCE}" -le "$MAX_INSTANCE_NAME_LEN" ] ||
    fail "derived instance name '${INSTANCE}' exceeds ${MAX_INSTANCE_NAME_LEN} characters"
}

run_bootroot() {
  (cd "$WORK_DIR" && BOOTROOT_LANG=en "$BOOTROOT_BIN" "$@")
}

# `bootroot` as root, for the one command that has to be.
#
# `env` rather than `sudo -E`: only the three variables named here cross
# the boundary.  `BOOTROOT_LANG` keeps the run on the English strings
# every assertion below matches on, and `HOME` stays the invoking user's
# because `init` drives the Docker CLI, which reads its client
# configuration — the daemon endpoint and any credential helper — out of
# `$HOME/.docker`.  Root's own `HOME` has none of that.
#
# `BOOTROOT_HTTP01_IMAGE` is the run-scoped responder tag this scenario
# built locally, and the compose file interpolates it with a default of
# the *untagged* repository name.  Dropping it at the sudo boundary does
# not fall back to the image on this host: it names one that exists in
# no registry, and the `docker compose up` `init` performs for the
# responder override fails on a pull nobody can satisfy.
run_bootroot_as_root() {
  (cd "$WORK_DIR" && sudo -n env \
    BOOTROOT_LANG=en \
    HOME="$HOME" \
    BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE" \
    "$BOOTROOT_BIN" "$@")
}

instance_compose() {
  BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" \
    -f "$WORK_DIR/$COMPOSE_FILE_NAME" "$@"
}

allocate_ports() {
  local suffix var
  for suffix in POSTGRES OPENBAO STEPCA HTTP01; do
    var="PORT_${suffix}"
    pick_free_port
    printf -v "$var" '%s' "$PICKED_PORT"
  done
  log "ports: postgres=${PORT_POSTGRES} openbao=${PORT_OPENBAO} stepca=${PORT_STEPCA} http01=${PORT_HTTP01}"
}

create_run_root() {
  RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bootroot-registrar-internal-init-XXXXXX")"
  WORK_DIR="$RUN_ROOT/bootroot"
  SECRETS_DIR="$WORK_DIR/secrets"
  INTERNAL_DIR="$SECRETS_DIR/registrar-internal"
  INIT_SUMMARY_JSON="$RUN_ROOT/init-summary.json"
  OPENBAO_ROOT_TOKEN_FILE="$RUN_ROOT/openbao-root-token"
  OPENBAO_CURL_CONFIG="$RUN_ROOT/openbao-curl.conf"
  mkdir -p "$WORK_DIR/openbao"
  # `docker-compose.deploy.yml` carries no build context, so a directory
  # holding a copy of it plus the two configs it resolves relative to
  # itself is a complete install root.
  cp "$ROOT_DIR/$COMPOSE_FILE_NAME" "$WORK_DIR/$COMPOSE_FILE_NAME"
  cp "$ROOT_DIR/openbao/openbao.hcl" "$WORK_DIR/openbao/openbao.hcl"
  cp "$ROOT_DIR/responder.toml.compose" "$WORK_DIR/responder.toml.compose"
  log "run root: $RUN_ROOT"
}

# The audit store's parent.
#
# Every obvious location fails the ancestor rule `bootroot init`
# enforces, which requires each existing component above the store to be
# a non-symlink directory carrying `o+x`: `RUN_ROOT` is a `mktemp -d`
# and so `0700`, and loosening it is not the answer since it holds the
# run's secrets tree; `$TMPDIR` is a `0700` per-user directory on macOS;
# the logical `/tmp` is a symbolic link to `private/tmp` there; and
# anywhere under the checkout inherits a developer home that is often
# `0750`.
#
# So `/tmp` is resolved *physically* and the directory is created from an
# explicit `mktemp -d` template under that resolved base, which is what
# keeps `$TMPDIR` from being consulted at all.
create_audit_store_base() {
  local physical_tmp
  physical_tmp="$(cd -P /tmp && pwd -P)" ||
    fail "could not resolve the physical /tmp"
  AUDIT_STORE_BASE="$(mktemp -d "${physical_tmp}/bootroot-audit-store-XXXXXX")" ||
    fail "could not create the audit store base under ${physical_tmp}"
  chmod 0755 "$AUDIT_STORE_BASE" ||
    fail "could not make ${AUDIT_STORE_BASE} world-traversable"
  AUDIT_STORE_DIR="$AUDIT_STORE_BASE/audit-store"
  log "audit store base: $AUDIT_STORE_BASE"
  assert_audit_store_base_is_traversable
}

# Asserts the harness's own precondition before `init` sees it, so a
# drifting temporary-directory layout fails here with its own message
# rather than through `init`'s ancestor error.
assert_audit_store_base_is_traversable() {
  local component="" part mode
  local -a parts=()
  IFS='/' read -r -a parts <<<"${AUDIT_STORE_BASE#/}"
  for part in "${parts[@]}"; do
    component="${component}/${part}"
    [ ! -L "$component" ] || fail "${component} is a symbolic link"
    [ -d "$component" ] || fail "${component} is not a directory"
    mode="$(stat -c '%a' "$component" 2>/dev/null || stat -f '%OLp' "$component")"
    case "$((8#${mode} & 1))" in
      1) ;;
      *) fail "${component} is at mode ${mode} and is not world-traversable" ;;
    esac
  done
  pass "every component above the audit store is a world-traversable directory"
}

build_responder_image() {
  if docker image inspect "$HTTP01_IMAGE" >/dev/null 2>&1; then
    log "reusing $HTTP01_IMAGE"
    return 0
  fi
  log "building $HTTP01_IMAGE"
  # `docker build` rather than `docker compose build` so the
  # repository's own `.env` and compose project are never read.
  docker build -t "$HTTP01_IMAGE" \
    -f "$ROOT_DIR/docker/http01-responder/Dockerfile" "$ROOT_DIR" \
    >>"$RUN_LOG" 2>&1 || fail "failed to build $HTTP01_IMAGE"
  HTTP01_IMAGE_BUILT=1
}

# `--no-build` implies `--pull never`, so the third-party images have to
# be on the host first.  Pulled through Compose so the tags come from the
# compose file rather than a second copy of them here.
prepull_third_party_images() {
  log "pre-pulling third-party images"
  POSTGRES_PASSWORD=prepull-only GRAFANA_ADMIN_PASSWORD=prepull-only \
    BOOTROOT_INSTANCE="$INSTANCE" \
    docker compose -p "$INSTANCE" -f "$WORK_DIR/$COMPOSE_FILE_NAME" \
    pull openbao postgres step-ca >>"$RUN_LOG" 2>&1 ||
    fail "failed to pre-pull the third-party images"
}

install_infra() {
  log "installing instance ${INSTANCE}"
  run_bootroot infra install \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --instance-name "$INSTANCE" \
    --postgres-host-port "$PORT_POSTGRES" \
    --openbao-host-port "$PORT_OPENBAO" \
    --stepca-host-port "$PORT_STEPCA" \
    --http01-admin-host-port "$PORT_HTTP01" \
    --no-build \
    >>"$RUN_LOG" 2>&1 || fail "infra install failed"
}

# `infra install` returns when every container reports `running`, which
# is not when the servers inside accept connections.  `init` opens with
# single-shot probes that do not retry, so the wait belongs here.
wait_for_openbao_listening() {
  local code
  for _ in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    code="$(curl -kSs -o /dev/null -w '%{http_code}' -m 3 \
      "http://127.0.0.1:${PORT_OPENBAO}/v1/sys/seal-status" 2>/dev/null || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs "${INSTANCE}-openbao" >>"$RUN_LOG" 2>&1 || true
  fail "OpenBao did not answer on port ${PORT_OPENBAO} before init"
}

wait_for_postgres_admin() {
  for _ in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec "${INSTANCE}-postgres" pg_isready -h 127.0.0.1 -U step -d postgres \
      >/dev/null 2>&1 &&
      bash -c ": >/dev/tcp/127.0.0.1/${PORT_POSTGRES}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs "${INSTANCE}-postgres" >>"$RUN_LOG" 2>&1 || true
  fail "PostgreSQL did not accept connections on port ${PORT_POSTGRES} before init"
}

# The predicate `init` consumes.  Written here rather than by a command
# because no command writes it yet: defining and storing it belongs to
# the registrar endpoint work, and this scenario is about what `init`
# does when it finds it.
seed_registrar_endpoint_predicate() {
  local state="$WORK_DIR/state.json" tmp="$WORK_DIR/state.json.seed"
  if [ -f "$state" ]; then
    jq --arg d "$DOMAIN" --arg h "$HOST_LABEL" \
      '.registrar_endpoint = {enabled: true, domain: $d, host: $h}' \
      "$state" >"$tmp" || fail "could not seed the predicate into $state"
  else
    jq -n --arg url "http://localhost:${PORT_OPENBAO}" --arg d "$DOMAIN" --arg h "$HOST_LABEL" \
      '{openbao_url: $url, kv_mount: "secret",
        registrar_endpoint: {enabled: true, domain: $d, host: $h}}' \
      >"$tmp" || fail "could not write $state"
  fi
  mv "$tmp" "$state"
  assert_equal "the predicate is recorded as enabled" \
    "true" "$(jq -r '.registrar_endpoint.enabled' "$state")"
  # The plaintext URL is the starting point the transition has to move:
  # asserting it here is what makes the `https://` assertion afterwards
  # a change rather than a coincidence.
  case "$(jq -r '.openbao_url' "$state")" in
    http://*) pass "OpenBao is recorded on a plaintext URL before init" ;;
    *) fail "state.json does not start on a plaintext URL" ;;
  esac
}

# The operator's `bootroot-agent` configuration file, which `init` reads
# through `--agent-config`.
#
# `[registrar] audit_store_dir` is the only definition of where the
# shared audit store lives, and `[registrar_endpoint] enabled` is
# cross-checked against the predicate seeded above — `init` refuses to
# proceed when the two disagree, so both say `true` here.
#
# Nothing in this scenario starts a `bootroot-agent` daemon, so an
# enabled `[registrar_endpoint]` in a file only the installer reads
# starts nothing and refuses nothing.
#
# `audit_store_enforcement = "directory"` is deliberate and is what the
# rest of this scenario is about: the store's layout, its ownership
# contract, the rendered Compose override and the device that lands on
# it.  The shipped `filesystem` default puts a loopback-backed reserve
# under `audit_store_dir`, which needs a loop device, `mkfs.ext4` and a
# live systemd on the host — none of which a container-based CI runner
# has.  `filesystem` mode's own phase-1 and phase-3 behaviour is
# asserted separately below, where it needs none of those.
seed_agent_configuration() {
  AGENT_CONFIG_FILE="$WORK_DIR/operator-agent.toml"
  cat >"$AGENT_CONFIG_FILE" <<EOF
[registrar]
audit_store_dir = "${AUDIT_STORE_DIR}"
audit_store_enforcement = "directory"

[registrar_endpoint]
enabled = true
EOF
  [ -s "$AGENT_CONFIG_FILE" ] || fail "could not write $AGENT_CONFIG_FILE"
  pass "the operator configuration names the audit store and agrees with the predicate"
}

# The `bootroot-agent` configuration a `filesystem`-mode section runs
# under.
#
# The reserve every caller passes is the smallest one that clears the
# mode's minimum, so the free-space preflight asks this runner for
# 16 MiB rather than for the shipped 2 GiB default, and the two record
# keys are what that minimum is derived from -- named here rather than
# defaulted so the figure the refusal would quote is this file's and not
# a shipped default's.
#
# `[registrar_endpoint] enabled` agrees with the predicate seeded into
# `state.json`; `init` refuses to proceed when the two disagree.
write_reserve_agent_config() {
  local path="$1" store="$2" reserve="$3"
  cat >"$path" <<EOF
[registrar]
audit_store_dir = "${store}"
audit_store_enforcement = "filesystem"
audit_store_reserve_bytes = ${reserve}
audit_store_low_water_bytes = 1024
audit_max_file_bytes = 65536
audit_max_retained_files = 1

[registrar_endpoint]
enabled = true
EOF
  [ -s "$path" ] || fail "could not write $path"
}

# `filesystem` mode stops the run at **provisioned, not activated** and
# performs no phase-2 step whatever.
#
# Run before `run_init`, against a store path of its own, so it sees the
# host as a fresh one: no rendered override to cross-check, and a store
# directory nothing has created.  It reaches the audit store step of
# `bootroot init` — which runs before any Docker call — and fails there,
# so nothing of the deployment is touched either.
#
# Every assertion here is about what bootroot may do to the host, which
# is why it needs no loop device: bootroot issues no `mkfs`, installs no
# unit, runs no `systemctl` and mounts nothing.  It renders those as
# commands and stops.
#
# This is also the boot-path containment case, with the mount unit not
# enabled: no bootroot code path creates `<audit_store_dir>/openbao` or
# `records/`, none runs a mount-establishing command, and no run reports
# **enforced**.  What Docker and the OpenBao container would do against
# an unmounted store is **deliberately not asserted** here.  The rendered
# Compose override is left byte-identical by this change, so a container
# brought back by `restart: always` still has Docker manufacture the bind
# source under the empty mount point; closing that is the bind guard's,
# and it belongs to the installer fail-closed issue rather than here.
assert_filesystem_mode_stops_before_it_touches_the_host() {
  local store config log artifacts unit
  store="$AUDIT_STORE_BASE/reserve-store"
  config="$WORK_DIR/operator-agent-filesystem.toml"
  log="$ARTIFACT_DIR/init-filesystem-mode.log"
  artifacts="$WORK_DIR/audit-store"

  write_reserve_agent_config "$config" "$store" 16777216

  if run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --agent-config "$config" \
    </dev/null >"$log" 2>&1; then
    fail "filesystem mode reported success on an unactivated host; see $log"
  fi
  grep -q "provisioned, not activated" "$log" ||
    fail "the run did not report provisioned, not activated; see $log"
  grep -q "ownership is not verified" "$log" ||
    fail "the outcome does not state that openbao/ ownership was not verified"
  pass "filesystem mode reports provisioned, not activated and stops"

  # The one filesystem object bootroot creates is the mount point.
  sudo -n test -d "$store" || fail "the mount point $store was not created"
  if sudo -n test -e "$store/records"; then
    fail "filesystem mode created records/ beneath an unmounted store"
  fi
  if sudo -n test -e "$store/openbao"; then
    fail "filesystem mode created openbao/ beneath an unmounted store"
  fi
  if sudo -n test -e "${store}.img"; then
    fail "bootroot created the loopback image itself"
  fi
  pass "only the mount point was created: no subdirectories and no image"

  # The three artifacts are written, and they are inert.
  unit="$(find "$artifacts" -maxdepth 1 -name '*.mount' -print -quit)"
  [ -n "$unit" ] || fail "no .mount unit was rendered under $artifacts"
  [ -f "$artifacts/docker.service.d/10-bootroot-audit-store.conf" ] ||
    fail "the docker.service drop-in was not rendered"
  [ -f "$artifacts/bootroot-registrar.service.d/10-bootroot-audit-store.conf" ] ||
    fail "the bootroot-registrar.service drop-in was not rendered"
  grep -qF "Where=${store}" "$unit" || fail "the unit does not mount $store"
  grep -qF "What=${store}.img" "$unit" || fail "the unit does not name the derived image"
  grep -q "^Options=loop$" "$unit" || fail "the unit is not loop-backed"
  grep -q "^Type=ext4$" "$unit" || fail "the unit is not ext4"
  for dropin in docker.service.d bootroot-registrar.service.d; do
    grep -q "^Wants=" "$artifacts/$dropin/10-bootroot-audit-store.conf" ||
      fail "$dropin lost its Wants="
    grep -q "^After=" "$artifacts/$dropin/10-bootroot-audit-store.conf" ||
      fail "$dropin lost its After="
    if grep -Eq "^(Requires|BindsTo|RequiresMountsFor)=" \
      "$artifacts/$dropin/10-bootroot-audit-store.conf"; then
      fail "$dropin carries a hard relation"
    fi
  done
  pass "the three artifacts are rendered, loop-backed and ordered only"

  # The unit name is systemd's own, not this implementation's idea of
  # it, where a `systemd-escape` exists to say so.
  if command -v systemd-escape >/dev/null 2>&1; then
    assert_equal "the rendered unit name matches systemd-escape --path" \
      "$(systemd-escape --path "$store").mount" "$(basename "$unit")"
  else
    log "systemd-escape is not on this host; the unit name comparison is skipped"
  fi

  # The rendered image commands carry both flags, for the two different
  # failures each of them prevents.
  grep -q -- "mkfs.ext4 -m 0 -E nodiscard,lazy_itable_init=0" "$log" ||
    fail "the rendered mkfs.ext4 is missing -m 0 or one of its -E options"
  grep -q -- "install -m 0600 /dev/null" "$log" ||
    fail "an absent image did not render its install"
  grep -q -- "if command -v fallocate" "$log" ||
    fail "an absent image did not render its allocation fallback"
  grep -q -- "fallocate -l 16777216" "$log" ||
    fail "an absent image did not retain its fallocate allocation route"
  grep -q -- "dd if=/dev/zero" "$log" ||
    fail "an absent image did not render its zero-fill allocation route"
  pass "the rendered image commands are the absent-image row, in full"

  # `bootroot infra up` is never named as the way to render or verify
  # the reserve.
  if grep -q "infra up" "$log"; then
    fail "the outcome tells the operator to run infra up"
  fi
  pass "no rendered step names bootroot infra up"

  # Nothing of `/etc/systemd/system` was written by that run.
  for installed in \
    "/etc/systemd/system/$(basename "$unit")" \
    "/etc/systemd/system/docker.service.d/10-bootroot-audit-store.conf" \
    "/etc/systemd/system/bootroot-registrar.service.d/10-bootroot-audit-store.conf"; do
    if sudo -n test -e "$installed"; then
      fail "bootroot installed $installed itself"
    fi
  done
  pass "bootroot installed no unit and no drop-in"

  # Leave the compose directory as `run_init` expects to find it: the
  # artifacts above belong to a store this scenario does not go on to
  # use.  Both were created by the root-run `init`, so both need `sudo`
  # to remove -- a plain `rm -rf` fails on them and, under `set -e`,
  # aborts the run.
  sudo -n rm -rf "$artifacts" "$store"
  remove_rendered_audit_override
}

# Removes the Compose override the run above rendered.
#
# `apply_audit_store` renders it *before* it verifies, so a run that
# stops at `provisioned, not activated` still leaves one on disk -- and
# it names that run's throwaway store.  `plan_audit_store` cross-checks
# a rendered override against the store the next `--agent-config`
# resolves and refuses the two when they differ, so leaving it behind
# would refuse every later run in this scenario, `run_init` included,
# with the stale-override error rather than with its own verdict.
remove_rendered_audit_override() {
  sudo_to_log rm -f "$WORK_DIR/secrets/openbao/docker-compose.openbao-audit.yml" || true
}

# A reinit whose configured reserve has not yet been activated must get
# past the destructive boundary, enter the ordinary init pass, and stop
# with precisely the same phase-two guidance as direct init. The first
# filesystem-mode assertion above covers the direct invocation; this one
# covers the recovery sequence between the wipe and that invocation.
assert_reinit_defers_a_fresh_filesystem_reserve_to_init() {
  local store config log direct_log before_container after_container direct_commands reinit_commands
  store="$AUDIT_STORE_BASE/reinit-reserve-store"
  config="$WORK_DIR/operator-agent-reinit-filesystem.toml"
  log="$ARTIFACT_DIR/reinit-filesystem-mode.log"
  direct_log="$ARTIFACT_DIR/init-reinit-filesystem-mode.log"

  # The existing directory-mode override belongs to the deployment we
  # have just exercised. Removing it makes this reserve fixture fresh:
  # reinit's pre-wipe `infra up` has no override to read, and its ordinary
  # init pass must render the one for `store` after the wipe.
  remove_rendered_audit_override
  if [ -e "$WORK_DIR/secrets/openbao/docker-compose.openbao-audit.yml" ]; then
    fail "could not remove the audit override before fresh-reserve reinit"
  fi
  write_reserve_agent_config "$config" "$store" 16777216

  # Establish the direct-init baseline with the identical configuration,
  # then return the reserve to its fresh state before asking reinit to
  # traverse the same init path.
  if run_bootroot_as_root init \
    --no-eab \
    --skip responder-check \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --agent-config "$config" \
    </dev/null >"$direct_log" 2>&1; then
    fail "direct init reported success on an unactivated filesystem reserve; see $direct_log"
  fi
  grep -q "provisioned, not activated" "$direct_log" ||
    fail "direct init did not reach the unactivated-reserve outcome; see $direct_log"
  direct_commands="$(sed -n '/Run these as root, in order, then run the command in the last step:/,/ownership is not verified/p' "$direct_log" | sed -n 's/^       //p')"
  [ -n "$direct_commands" ] ||
    fail "direct init rendered no phase-two commands; see $direct_log"
  sudo -n rm -rf "$WORK_DIR/audit-store" "$store"
  remove_rendered_audit_override
  [ ! -e "$WORK_DIR/secrets/openbao/docker-compose.openbao-audit.yml" ] ||
    fail "could not reset the direct-init reserve fixture before reinit"

  before_container="$(docker inspect --format '{{.Id}}' "${INSTANCE}-openbao")"

  if run_bootroot_as_root reinit \
    --yes \
    --no-eab \
    --skip responder-check \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --agent-config "$config" \
    </dev/null >"$log" 2>&1; then
    fail "reinit reported success on an unactivated filesystem reserve; see $log"
  fi

  # Reaching a different container proves reinit crossed its wipe and
  # used the ordinary infra-up handoff; reaching this outcome proves the
  # following init pass, rather than the preflight, rendered the reserve.
  after_container="$(docker inspect --format '{{.Id}}' "${INSTANCE}-openbao")"
  [ "$before_container" != "$after_container" ] ||
    fail "reinit did not replace OpenBao before the filesystem outcome; see $log"
  grep -q "provisioned, not activated" "$log" ||
    fail "reinit did not reach init's unactivated-reserve outcome; see $log"
  [ -f "$WORK_DIR/secrets/openbao/docker-compose.openbao-audit.yml" ] ||
    fail "ordinary init did not render the audit override after reinit"
  [ -d "$WORK_DIR/audit-store" ] ||
    fail "ordinary init did not render the reserve artifacts after reinit"

  # The outcome is not merely similar: the complete ordered command
  # sequence must exactly match direct init with the same inputs.
  reinit_commands="$(sed -n '/Run these as root, in order, then run the command in the last step:/,/ownership is not verified/p' "$log" | sed -n 's/^       //p')"
  [ "$reinit_commands" = "$direct_commands" ] ||
    fail "reinit's phase-two commands differ from direct init; see $direct_log and $log"
  assert_equal "reinit restores the enabled endpoint predicate before init" \
    "true" "$(jq -r '.registrar_endpoint.enabled' "$WORK_DIR/state.json")"
  pass "fresh filesystem reinit reaches ordinary init with direct-init phase-two guidance"
}

# One elevated command, with its output appended to this run's log.
#
# The redirect is the invoking user's, not `sudo`'s, which is the
# intent: `$RUN_LOG` is that user's own file and stays readable by them
# afterwards.
# shellcheck disable=SC2024
sudo_to_log() {
  sudo -n "$@" >>"$RUN_LOG" 2>&1
}

# Whether this host can carry an activated reserve at all.
#
# The activation below is the operator's own phase-2 sequence run
# verbatim, so it needs everything that sequence names: a live systemd
# to enable the generated `.mount` unit under, `mkfs.ext4`, `dd`, and a
# kernel with loop devices. `fallocate` is optional because the rendered
# image command falls back to `dd` when it is unavailable. A
# host missing any of them skips the section with a line saying so --
# the macOS preflight runs this same scenario, and there `systemctl`
# does not exist at all.
reserve_activation_is_possible() {
  [ -d /run/systemd/system ] || return 1
  command -v systemctl >/dev/null 2>&1 || return 1
  command -v mkfs.ext4 >/dev/null 2>&1 || return 1
  command -v dd >/dev/null 2>&1 || return 1
  command -v losetup >/dev/null 2>&1 || return 1
  command -v blkid >/dev/null 2>&1 || return 1
  sudo -n test -e /dev/loop-control || return 1
}

# The rendered phase-2 commands, pasted into a shell exactly as printed.
#
# Reading them back out of the outcome rather than restating them here
# is the point: an operator's only source for these is that text, so a
# command it renders wrong -- a store path whose spaces or backslashes
# lost their quoting, a unit name `sh` ate the `\x2d` out of -- fails
# here rather than in a deployment.  Two lines are the caller's and are
# not run: step 1 names a unit no CI host has installed, and step 5 is
# the re-run this function performs itself, with the flags this scenario
# needs.
run_rendered_phase_two() {
  local log="$1" line
  while IFS= read -r line; do
    case "$line" in
      "systemctl stop "*) continue ;;
      "bootroot init"*) continue ;;
    esac
    log "running rendered step: $line"
    sudo_to_log sh -c "$line" ||
      fail "a rendered phase-2 command failed: $line"
  done < <(sed -n 's/^       \(.*\)$/\1/p' "$log")
}

# Everything the reserve is for, end to end: the rendered commands
# activate it, the re-run reports **enforced**, a second re-run changes
# nothing, and a write past the reserve stops at the reserve instead of
# at the host's root filesystem.
assert_the_rendered_steps_activate_the_reserve() {
  local config log store image unit reserve=16777216
  if ! reserve_activation_is_possible; then
    log "this host has no systemd, loop device or mkfs.ext4; the activation section is skipped"
    return 0
  fi
  store="$AUDIT_STORE_BASE/reserve-active"
  image="${store}.img"
  config="$WORK_DIR/operator-agent-activate.toml"
  log="$ARTIFACT_DIR/init-reserve-activate.log"

  write_reserve_agent_config "$config" "$store" "$reserve"

  if run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "$RESERVE_DEAD_OPENBAO_URL" \
    --agent-config "$config" \
    </dev/null >"$log" 2>&1; then
    fail "the first run reported success on an unactivated host; see $log"
  fi
  grep -q "provisioned, not activated" "$log" ||
    fail "the first run did not report provisioned, not activated; see $log"

  # `|| unit=""` rather than letting the assignment fail the run: an
  # absent staging directory is this scenario's own message to give,
  # not `set -e`'s silence.
  unit="$(basename "$(find "$WORK_DIR/audit-store" -maxdepth 1 -name '*.mount' -print -quit)")" ||
    unit=""
  [ -n "$unit" ] || fail "no .mount unit was rendered under $WORK_DIR/audit-store"
  # Recorded before the first host-changing command, so cleanup can
  # undo whatever the sequence got through.
  RESERVE_STORE_DIR="$store"
  RESERVE_IMAGE="$image"
  RESERVE_UNIT_NAME="$unit"

  run_rendered_phase_two "$log"
  pass "every rendered phase-2 command ran verbatim"

  # The unit systemd loaded names the paths that were configured, byte
  # for byte, which is the assertion a unit-name or `Where=` escaping
  # bug fails.
  assert_equal "the rendered unit name matches systemd-escape --path" \
    "$(systemd-escape --path "$store").mount" "$unit"
  assert_equal "the loaded unit mounts the configured store" \
    "Where=${store}" "$(sudo -n systemctl show -p Where "$unit")"
  assert_equal "the mount unit is active" \
    "ActiveState=active" "$(sudo -n systemctl show -p ActiveState "$unit")"
  # `What=` reads back as the loop device once the mount is up rather
  # than as the file the unit names, so the image is confirmed the way
  # the verification itself confirms it: through the device's backing
  # file.
  local source
  source="$(sudo -n systemctl show -p What --value "$unit")"
  assert_equal "the mount is on a loop device backed by the derived image" \
    "$image" "$(sudo -n losetup -O BACK-FILE --noheadings "$source" | sed 's/^ *//;s/ *$//')"

  # The two `-E` options are what keep the image's blocks where the
  # preallocation put them.  `nodiscard` stops `mke2fs` from discarding
  # them as it writes the filesystem, which on a loop device is a hole
  # punch through to the backing file.  `lazy_itable_init=0` stops the
  # kernel's `ext4lazyinit` thread from zeroing the inode tables a few
  # seconds *after* the mount comes up, which the loop driver serves the
  # same way -- so this assertion is deliberately made after the mount
  # is active and the subdirectories are on it, which is the window that
  # background thread runs in.  Either one missing leaves an image that
  # passes every size check while the root filesystem is still what
  # fills.
  #
  # `>=` rather than `=`, and it is the same comparison the verification
  # itself makes: `st_blocks` counts the *hosting* filesystem's blocks,
  # so a file whose extents no longer fit in its inode carries an extent
  # tree block on top of its own length.  On the CI runner this image
  # measures one 4 KiB block above the reserve.  What "fully allocated"
  # asserts is that nothing of the image's own length is a hole, which
  # is `allocated >= size`; an equality here would be a test that fails
  # on the host's extent layout rather than on anything bootroot did.
  local allocated
  allocated="$(( $(sudo -n stat -c %b "$image") * 512 ))"
  # Logged unconditionally: this is the one figure in the section that
  # the host, rather than bootroot, has the last word on, so a run that
  # fails here has to say by how much and a run that passes has to leave
  # the number behind for the next one to be compared against.
  log "image allocation after mkfs: $(sudo -n stat -c 'size=%s blocks=%b unit=%B' "$image")"
  assert_at_least "the image is fully allocated once the mount is up" \
    "$reserve" "$allocated"
  assert_equal "the image is the size of the reserve" \
    "$reserve" "$(sudo -n stat -c %s "$image")"
  assert_equal "the image is root-owned at 0600" "0:0:600" "$(file_owner_mode "$image")"

  # The subdirectories are on the mounted filesystem rather than on the
  # directory underneath it.
  assert_equal "records/ sits on the mounted reserve" \
    "$(store_device "$store")" "$(store_device "$store/records")"
  assert_equal "records/ is root-owned at 0700" "0:0:700" \
    "$(file_owner_mode "$store/records")"
  assert_equal "openbao/ is at 0700" "700" \
    "$(sudo -n stat -c %a "$store/openbao")"
  # The store directory itself, which is the *mounted filesystem's* root
  # once the mount is up.  `mkfs.ext4` gives that root `0755`, and the
  # store directory contract -- the one `bootroot infra up` applies to
  # the path the rendered override names -- is exactly `0700`, so the
  # rendered step 4 restates it.  Asserting the result here is what
  # keeps that command from being rendered and never confirmed: without
  # it, a run reaches **enforced** and the next `bootroot infra up`
  # refuses the store it just activated.
  assert_equal "the mounted store directory is root-owned at 0700" "0:0:700" \
    "$(file_owner_mode "$store")"

  # Inode, size and the ext4 UUID -- one term per word of the claim:
  # a recreated image is a new inode, a resized one a new size, a
  # reformatted one a new filesystem UUID.
  #
  # Deliberately *not* `st_blocks` or mtime, which the first draft of
  # this assertion used and which are both unstable here for reasons
  # that have nothing to do with bootroot.  The image is a mounted
  # filesystem's backing file for the whole window: ext4 commits its
  # journal and rewrites its superblock through the loop device every
  # few seconds, which moves mtime, and the host's own allocation
  # bookkeeping moves `st_blocks`.  Neither is part of "recreated,
  # resized or reformatted", and the allocation is asserted on its own
  # above.
  local before after
  before="$(image_identity "$image")"
  if run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "$RESERVE_DEAD_OPENBAO_URL" \
    --agent-config "$config" \
    </dev/null >"${log}.2" 2>&1; then
    : # This run reaches **enforced** and would otherwise carry on into
      # the initialisation proper; the dead URL above stops it at the
      # OpenBao health check instead.  The audit store outcome is what
      # this asserts, and it is printed before that.
  fi
  grep -q "enforced (filesystem)" "${log}.2" ||
    fail "the re-run did not report enforced; see ${log}.2"
  grep -q "ownership is not verified" "${log}.2" ||
    fail "the enforced outcome does not carry the openbao/ ownership caveat"
  pass "the re-run reports enforced"

  # Re-provisioning is idempotent and never reformats: no image command
  # is rendered at all, and the image is the one that was already there.
  if grep -Eq "mkfs\.ext4|install -m 0600|command -v fallocate|dd if=" "${log}.2"; then
    fail "the re-run rendered an image command over an activated reserve; see ${log}.2"
  fi
  after="$(image_identity "$image")"
  assert_equal "the image was not recreated, resized or reformatted" "$before" "$after"

  # The allocation again, and this one is the assertion that catches a
  # missing `lazy_itable_init=0`.  The check above runs seconds after
  # the mount, which is before the kernel's background inode-table pass
  # has had a chance to hand those blocks back; the re-run in between
  # is a whole `bootroot init` and covers that window without this
  # scenario having to sleep through it.
  log "image allocation after the re-run: $(sudo -n stat -c 'size=%s blocks=%b unit=%B' "$image")"
  assert_at_least "the image is still fully allocated after the re-run" \
    "$reserve" "$(( $(sudo -n stat -c %b "$image") * 512 ))"

  # The ceiling, which is the whole point: a write past the reserve
  # fails on the reserve, and the host's root filesystem is not what
  # absorbs it.
  local root_before root_after
  root_before="$(df -P -k / | awk 'NR==2 {print $4}')"
  if sudo_to_log dd if=/dev/zero of="$store/records/fill" bs=1M count=64; then
    fail "a write of four times the reserve succeeded; the ceiling is not enforced"
  fi
  assert_equal "the overflowing file stopped inside the reserve" "yes" \
    "$([ "$(sudo -n stat -c %s "$store/records/fill")" -lt "$reserve" ] && echo yes || echo no)"
  root_after="$(df -P -k / | awk 'NR==2 {print $4}')"
  # A tolerance rather than an equality: this is a live host and other
  # things write to it while the assertion runs.  What it catches is the
  # reserve's worth of bytes landing on the root filesystem, which is
  # four orders of magnitude above the noise.
  assert_equal "the root filesystem did not absorb the overflow" "yes" \
    "$([ "$(( root_before - root_after ))" -lt 8192 ] && echo yes || echo no)"
  sudo -n rm -f "$store/records/fill"

  remove_reserve_activation
  # Leave the compose directory as `run_init` expects to find it: the
  # staged artifacts and the rendered override both name this section's
  # own store, and the override would refuse every later run.
  sudo -n rm -rf "$WORK_DIR/audit-store"
  remove_rendered_audit_override
}

# Takes the activation back off the host, in the order the manual's
# removal sequence gives: disable the mount, remove the unit and both
# drop-ins, reload, and only then delete the image.
remove_reserve_activation() {
  [ -n "$RESERVE_UNIT_NAME" ] || return 0
  sudo_to_log systemctl disable --now "$RESERVE_UNIT_NAME" || true
  # Belt and braces: a mount established by something other than the
  # unit, or one the disable could not stop, would otherwise be what the
  # store base's `rm -rf` descends into.
  sudo_to_log umount "$RESERVE_STORE_DIR" || true
  sudo_to_log rm -f \
    "/etc/systemd/system/$RESERVE_UNIT_NAME" \
    "/etc/systemd/system/docker.service.d/10-bootroot-audit-store.conf" \
    "/etc/systemd/system/bootroot-registrar.service.d/10-bootroot-audit-store.conf" || true
  sudo_to_log systemctl daemon-reload || true
  sudo_to_log rm -rf "$RESERVE_IMAGE" "$RESERVE_STORE_DIR" || true
  RESERVE_UNIT_NAME=""
  RESERVE_STORE_DIR=""
  RESERVE_IMAGE=""
}

# The store's directories are created owned by whoever creates them, so
# an unprivileged `init` on this host has to be refused before it makes
# one.  A user-owned store is exactly what the root run afterwards
# refuses as foreign-owned and, by contract, does not repair — so the
# refusal here is what keeps a mistaken `bootroot init` from locking the
# host out of provisioning without manual `chown`.
#
# Run through `run_bootroot` rather than `run_bootroot_as_root`, and
# before `run_init`, so the store it must not create is one nothing has
# created yet.
assert_an_unprivileged_init_is_refused() {
  local log="$ARTIFACT_DIR/init-unprivileged.log"
  local override="$WORK_DIR/secrets/openbao/docker-compose.openbao-audit.yml"
  if run_bootroot init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --enable auto-generate,show-secrets \
    --stepca-password "registrar-internal-${RUN_TOKEN}" \
    --http-hmac "dev-hmac-${RUN_TOKEN}" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --responder-url "http://127.0.0.1:${PORT_HTTP01}" \
    --agent-config "$AGENT_CONFIG_FILE" \
    </dev/null >"$log" 2>&1; then
    fail "an unprivileged 'bootroot init' was accepted on an endpoint-enabled host"
  fi
  grep -q "requires running as uid 0" "$log" ||
    fail "the unprivileged run failed for another reason; see $log"
  [ ! -e "$AUDIT_STORE_DIR" ] ||
    fail "the refused run created $AUDIT_STORE_DIR"
  [ ! -e "$override" ] ||
    fail "the refused run rendered $override"
  pass "an unprivileged init is refused before it creates a store or renders an override"
}

run_init() {
  log "initialising instance ${INSTANCE}"
  if ! run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-password "registrar-internal-${RUN_TOKEN}" \
    --http-hmac "dev-hmac-${RUN_TOKEN}" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --confirm-db-provision \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "http://127.0.0.1:${PORT_HTTP01}" \
    --agent-config "$AGENT_CONFIG_FILE" \
    --summary-json "$INIT_SUMMARY_JSON" \
    </dev/null >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 200 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed; see $INIT_RAW_LOG"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$ARTIFACT_DIR/init.log"
  # Root-owned, because the run that wrote it was.
  #
  # The token moves from the summary to its own file on a pipe and never
  # through an argument list: `jq` runs as the invoking user on `cat`'s
  # output, and the elevated shell that writes the file reads the value
  # from standard input.  `printf %s "$(cat)"` drops the newline `jq -r`
  # ends its output with, so the file is the token and nothing else, and
  # `umask 077` gives it mode `0600` as it is created rather than after.
  sudo -n cat "$INIT_SUMMARY_JSON" |
    jq -r '.root_token // empty' |
    sudo -n sh -c 'umask 077; printf %s "$(cat)" >"$1"' _ \
      "$OPENBAO_ROOT_TOKEN_FILE" 2>>"$RUN_LOG" ||
    fail "could not read the root token out of $INIT_SUMMARY_JSON"
  # Removed the moment it has been read, so the credential bundle lives
  # on disk for one command rather than for the rest of the run.  A run
  # that failed before here leaves it for `remove_run_root`.
  sudo -n rm -f "$INIT_SUMMARY_JSON" 2>>"$RUN_LOG" ||
    fail "could not remove $INIT_SUMMARY_JSON after reading it"
  sudo -n test -s "$OPENBAO_ROOT_TOKEN_FILE" ||
    fail "init recorded no root token in $INIT_SUMMARY_JSON"
  # The header every authenticated call below sends, as a `curl -K`
  # configuration file rather than as a `-H` argument.  Written by the
  # same elevated shell that reads the token, so the value crosses no
  # argument list here either.
  #
  # Nothing escapes the token into curl's quoted-string syntax because
  # nothing needs to: an OpenBao token is base64url text with a service
  # prefix, and carries neither a quote nor a backslash.
  sudo -n sh -c \
    'umask 077; printf "header = \"X-Vault-Token: %s\"\n" "$(cat "$1")" >"$2"' _ \
    "$OPENBAO_ROOT_TOKEN_FILE" "$OPENBAO_CURL_CONFIG" 2>>"$RUN_LOG" ||
    fail "could not stage the root token's curl configuration"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

assert_state_url_moved_to_https() {
  local url
  url="$(jq -r '.openbao_url' "$WORK_DIR/state.json")"
  assert_equal "the recorded OpenBao URL is this install's port over HTTPS" \
    "https://localhost:${PORT_OPENBAO}" "$url"
}

# The listener really terminates TLS: plaintext must not answer where
# HTTPS does.  Verified against the credential's *own* private bundle,
# never with `-k` — which asserts one more thing than a generic TLS
# probe would: that the bundle `init` wrote beside the credential really
# does anchor the listener the credential has to log in over.
assert_listener_serves_tls() {
  local bundle="$INTERNAL_DIR/ca-bundle.pem" code
  # Every read below is elevated because the directory these files sit
  # in is `0700` root-owned once a root-run `init` has created it — not
  # because the bundle itself is protected material, which it is not.
  sudo -n test -s "$bundle" || fail "the internal private CA bundle is missing at $bundle"
  code="$(sudo -n "$CURL_BIN" -sS -o /dev/null -w '%{http_code}' -m 10 --cacert "$bundle" \
    "https://localhost:${PORT_OPENBAO}/v1/sys/seal-status" 2>>"$RUN_LOG" || true)"
  [ "$code" = "200" ] || fail "the TLS listener did not answer 200 (got '${code}')"
  pass "the listener answers over TLS, verified against the credential's private bundle"

  # A TLS listener still accepts the TCP connection and answers a
  # plaintext request — with `400 Bad Request`, not the API. So the
  # assertion is on the status rather than on curl's exit code, which is
  # zero for any HTTP response at all.
  local plain
  plain="$(curl -sS -o /dev/null -w '%{http_code}' -m 5 \
    "http://localhost:${PORT_OPENBAO}/v1/sys/seal-status" 2>>"$RUN_LOG" || true)"
  [ "$plain" != "200" ] ||
    fail "the API still answers over plaintext on the transitioned listener"
  pass "the API no longer answers over plaintext (got '${plain}')"
}

assert_no_listener_client_cert_options() {
  local hcl="$WORK_DIR/openbao/openbao.hcl" option
  [ -f "$hcl" ] || fail "openbao.hcl is missing at $hcl"
  for option in tls_client_ca_file tls_require_and_verify_client_cert tls_disable_client_certs; do
    if grep -q "$option" "$hcl"; then
      fail "the listener configuration sets ${option}"
    fi
  done
  pass "the listener introduces no client-certificate option"
}

assert_material_is_complete_and_restrictive() {
  local name probe
  for name in key.pem chain.pem acme-account.json root-fingerprint agent.toml; do
    sudo -n test -s "$INTERNAL_DIR/$name" || fail "missing or empty: $INTERNAL_DIR/$name"
    # uid 0 and gid 0 are the criterion this run exists to prove: the
    # key and the ACME account key are unreadable to anyone but root,
    # and the config carrying the trust pins is unwritable to them.  The
    # mode is asserted alongside as the regression guard it has been
    # since #766.
    probe="$(file_owner_mode "$INTERNAL_DIR/$name")"
    [ "$probe" = "0:0:600" ] ||
      fail "${name} is uid:gid:mode ${probe}, expected 0:0:600"
  done
  pass "the five protected artifacts are root-owned at 0600"

  sudo -n test -s "$INTERNAL_DIR/ca-bundle.pem" || fail "missing the private CA bundle"
  pass "the private CA bundle exists"

  sudo -n test ! -d "$INTERNAL_DIR/.staging" ||
    fail "the staging directory survived a successful publication"
  pass "the staging directory was swept"

  # The prior-set snapshot the publication holds the old credential in.
  # A completed publication discards it; one that survives means the
  # publication (or the restore after it) did not finish.
  sudo -n test ! -d "$INTERNAL_DIR/.prior" ||
    fail "the prior-set snapshot survived a successful publication"
  pass "the prior-set snapshot was discarded"
}

assert_generated_config_is_the_internal_one() {
  local config="$INTERNAL_DIR/agent.toml" text
  # Read once, elevated, and matched in the shell: the config is
  # root-owned `0600` and holds the responder HMAC, so it is neither
  # readable here nor worth copying anywhere.
  text="$(sudo -n cat "$config")" || fail "the generated config could not be read at $config"
  grep -q "service_name = \"${INTERNAL_ENTRY}\"" <<<"$text" ||
    fail "the generated config does not name the fixed identity"
  grep -q "account_key_path = \"${INTERNAL_DIR}/acme-account.json\"" <<<"$text" ||
    fail "the generated config does not point at the persistent ACME account key"
  grep -q "ca_bundle_path = \"${INTERNAL_DIR}/ca-bundle.pem\"" <<<"$text" ||
    fail "the generated config does not point at the private CA bundle"
  # The endpoints follow this install's published ports.  On the compose
  # defaults a hard-coded value looks identical, which is why the ports
  # were moved.
  grep -q "server = \"https://localhost:${PORT_STEPCA}/acme/acme/directory\"" <<<"$text" ||
    fail "the generated config does not use this install's step-ca port"
  grep -q "http_responder_url = \"http://127.0.0.1:${PORT_HTTP01}\"" <<<"$text" ||
    fail "the generated config does not use this install's responder port"
  pass "the generated config names the fixed identity, its private trust and this install's ports"
}

assert_leaf_carries_the_fixed_san() {
  local san
  san="$(sudo -n "$PYTHON_BIN" - "$INTERNAL_DIR/chain.pem" <<'PY'
import re, ssl, sys, tempfile
pem = open(sys.argv[1]).read()
first = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S).group(0)
with tempfile.NamedTemporaryFile("w", suffix=".pem") as handle:
    handle.write(first + "\n")
    handle.flush()
    names = ssl._ssl._test_decode_cert(handle.name)
print(",".join(value for key, value in names.get("subjectAltName", ()) if key == "DNS"))
PY
  )" || fail "could not read the issued leaf"
  assert_equal "the issued leaf carries exactly the fixed internal SAN" "$INTERNAL_SAN" "$san"
}

# The criterion this scenario exists for: the credential `init` just
# published authenticates at `auth/cert` over the URL `init` just
# recorded.  Presented as a PEM client certificate through python3's
# `ssl`, which every platform this runs on supports.
assert_certificate_login_succeeds() {
  local out
  out="$(sudo -n "$PYTHON_BIN" - "$INTERNAL_DIR" "localhost" "$PORT_OPENBAO" "$INTERNAL_ENTRY" <<'PY'
import http.client, json, ssl, sys
cred, host, port, entry = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
context = ssl.create_default_context(cafile=f"{cred}/ca-bundle.pem")
context.load_cert_chain(certfile=f"{cred}/chain.pem", keyfile=f"{cred}/key.pem")
conn = http.client.HTTPSConnection(host, port, context=context, timeout=15)
conn.request("POST", "/v1/auth/cert/login", json.dumps({"name": entry}),
             {"Content-Type": "application/json"})
response = conn.getresponse()
body = json.loads(response.read())
auth = body.get("auth") or {}
print(json.dumps({
    "status": response.status,
    "has_token": bool(auth.get("client_token")),
    "policies": sorted(auth.get("token_policies") or auth.get("policies") or []),
}))
PY
  )" || fail "the certificate login raised; see the traceback above"
  assert_equal "the certificate login is accepted" "200" "$(jq -r .status <<<"$out")"
  assert_equal "the login returns a token" "true" "$(jq -r .has_token <<<"$out")"
  # `token_no_default_policy` is what makes the allowlist the whole
  # grant: a `default` here would widen it well past the verb paths.
  assert_equal "the minted token carries the exact allowlist and nothing else" \
    "[\"${INTERNAL_ENTRY}\"]" "$(jq -c .policies <<<"$out")"
}

# Without a client certificate the same endpoint must refuse: the
# credential is the certificate, so a login that succeeds without one
# would mean the entry is not the gate.
assert_login_without_the_certificate_is_refused() {
  local status
  status="$(sudo -n "$PYTHON_BIN" - "$INTERNAL_DIR" "localhost" "$PORT_OPENBAO" "$INTERNAL_ENTRY" <<'PY'
import http.client, json, ssl, sys
cred, host, port, entry = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
context = ssl.create_default_context(cafile=f"{cred}/ca-bundle.pem")
conn = http.client.HTTPSConnection(host, port, context=context, timeout=15)
conn.request("POST", "/v1/auth/cert/login", json.dumps({"name": entry}),
             {"Content-Type": "application/json"})
print(conn.getresponse().status)
PY
  )" || fail "the certificate-less login raised"
  [ "$status" != "200" ] || fail "a login with no client certificate was accepted"
  pass "a login with no client certificate is refused (${status})"
}

# Everything the OpenBao Agent sidecars open still belongs to the tree
# they run in, after a root-run `init` wrote all of it.
#
# They are the only containers `init` both configures and starts that
# run as an ordinary uid: the generated override launches each one as
# the owner of `secrets/`, which on this host is the invoking user and
# not the root that ran `init`.  Their `agent.hcl`, their `AppRole`
# pair, the `.ctmpl` files they render from and the `0700` directories
# all of those sit in must therefore carry that owner rather than the
# writing process's — a `0700` directory owned by root hides every file
# inside it whatever the file itself is owned by.
#
# Asserted on the tree rather than on container state, because a
# regression here is quiet from the outside: the containers still
# start, `init` still succeeds, and the renewals the sidecars exist to
# perform simply stop.
assert_the_infra_agent_tree_belongs_to_its_sidecars() {
  local owner probe path
  probe="$(file_owner_mode "$SECRETS_DIR")"
  owner="${probe%:*}"
  for path in \
    openbao \
    openbao/stepca \
    openbao/responder \
    openbao/stepca/agent.hcl \
    openbao/stepca/role_id \
    openbao/stepca/secret_id \
    openbao/responder/agent.hcl \
    openbao/responder/role_id \
    openbao/responder/secret_id \
    templates \
    templates/password.txt.ctmpl \
    templates/ca.json.ctmpl \
    templates/responder.toml.ctmpl \
    responder \
    responder/responder.toml \
    password.txt; do
    sudo -n test -e "$SECRETS_DIR/$path" || fail "missing: $SECRETS_DIR/$path"
    probe="$(file_owner_mode "$SECRETS_DIR/$path")"
    [ "${probe%:*}" = "$owner" ] ||
      fail "${path} is owned by ${probe%:*}, not by the secrets tree (${owner}) the sidecars run as"
  done
  pass "the sidecars' configuration, credentials and templates belong to the secrets tree"
}

# The two infra sidecars are generated before the TLS transition and
# started after it, so what they must be generated *for* is the listener
# the transition leaves behind: an `https://` address on the OpenBao
# container name, and the CA bundle that verifies its step-ca-signed
# leaf.  Generating them for the plaintext listener instead is invisible
# at bring-up — the containers start, `init` succeeds, and the two
# agents spend the rest of the deployment speaking HTTP to a TLS port,
# renewing nothing.  Asserted on the generated files so that regression
# fails here, with its reason, rather than as an audit log three phases
# later that carries no `auth/approle/login`.
assert_the_infra_agents_are_generated_for_tls() {
  local addr="https://${INSTANCE}-openbao:8200" agent config
  local override="$SECRETS_DIR/openbao/docker-compose.openbao-agent.override.yml"
  [ -f "$override" ] || fail "no infra agent compose override was rendered at $override"
  grep -qF "VAULT_ADDR=${addr}" "$override" ||
    fail "the agent override does not point the sidecars at ${addr}"
  for agent in stepca responder; do
    config="$SECRETS_DIR/openbao/${agent}/agent.hcl"
    grep -qF "address = \"${addr}\"" "$config" ||
      fail "the ${agent} agent config does not address ${addr}"
    grep -qF 'ca_cert = "/openbao/secrets/certs/ca-bundle.pem"' "$config" ||
      fail "the ${agent} agent config carries no CA bundle to verify the TLS leaf"
  done
  [ -f "$SECRETS_DIR/certs/ca-bundle.pem" ] ||
    fail "the CA bundle the sidecars verify the listener with is missing"
  pass "the infra sidecars are generated for the TLS listener the transition leaves behind"
}

# `bootroot infra up` over the deployment `init` just provisioned.
#
# `infra up` ends in a recursive ownership sweep: a one-shot root
# container that chowns everything below `secrets/` to that directory's
# own owner, so a `--user root` step helper cannot leave CA material
# step-ca and the sidecars are unable to read.  It is therefore the one
# routine command that could quietly undo everything asserted above —
# without any protected file being republished, and on a host where the
# operator did nothing more than restart the stack.  The same sweep is
# reached by `reinit` and by the CA and step-ca-password rotations, so
# covering it once here covers the shape of all of them.
#
# Run as the invoking user rather than through `sudo -n`, because that
# is the case that used to regress: the sweep's root container can chown
# the root-owned files whatever the invoking process could.
#
# `--openbao-url` is passed explicitly.  `init` transitioned the
# listener to TLS on this port, and `infra up`'s own derivation only
# ever replaces the port in the `http://` default, so the unseal probe
# would open a plaintext request against a TLS listener and never get an
# answer.
run_infra_up_over_the_initialised_deployment() {
  log "running 'infra up' over the initialised deployment"
  run_bootroot infra up \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --openbao-url "https://localhost:${PORT_OPENBAO}" \
    >>"$RUN_LOG" 2>&1 || fail "infra up failed after init"
  pass "'infra up' completed over the initialised deployment"
}

# The shared audit store, and the OpenBao file audit device now bound
# into it.
#
# Every read below goes through `sudo -n`: the store is root-owned
# `0700`, which is the whole point of the contract `init` holds it to.
assert_audit_store_is_provisioned() {
  local probe path
  sudo -n test -d "$AUDIT_STORE_DIR" || fail "the audit store is missing at $AUDIT_STORE_DIR"
  sudo -n test -d "$AUDIT_STORE_DIR/records" || fail "the store has no records/ directory"
  sudo -n test -d "$AUDIT_STORE_DIR/openbao" || fail "the store has no openbao/ directory"
  pass "the audit store exists with records/ and openbao/ beneath it"

  for probe in "" records; do
    path="$AUDIT_STORE_DIR${probe:+/$probe}"
    assert_equal "${path} is root-owned and 0700" "0:0:700" "$(file_owner_mode "$path")"
  done

  # The container's entrypoint chowns `/openbao/audit` on every start,
  # and against a bind mount that operates on the host directory.  So
  # `openbao/` belongs to the container's user by the time the stack is
  # up — which is exactly what `init` must not assert, repair or reject
  # on a re-run.
  probe="$(file_owner_mode "$AUDIT_STORE_DIR/openbao")"
  [ "${probe%%:*}" != "0" ] ||
    fail "openbao/ is still root-owned (${probe}); the container's entrypoint did not run against the bind mount"
  pass "openbao/ belongs to the container's user while the store and records/ stay root's"
}

# `directory` is a success, and it derives nothing: no image path, no
# unit name, no artifact, and no leftover named.
assert_the_directory_mode_outcome_is_a_success() {
  grep -q "unenforced (directory)" "$INIT_RAW_LOG" ||
    fail "the run did not report unenforced (directory); see $INIT_RAW_LOG"
  grep -q "project quota" "$INIT_RAW_LOG" ||
    fail "the directory outcome does not name the project-quota route"
  if grep -q "provisioned, not activated" "$INIT_RAW_LOG"; then
    fail "a directory-mode run reported a filesystem-mode outcome"
  fi
  if [ -e "$WORK_DIR/audit-store" ]; then
    fail "a directory-mode run rendered the reserve's artifacts"
  fi
  if sudo -n test -e "${AUDIT_STORE_DIR}.img"; then
    fail "a directory-mode run created a loopback image"
  fi
  pass "directory mode reports unenforced (directory) and derives nothing"
}

# The rendered override is what moved the device, and it is the record
# `bootroot infra up` reads the bind source back out of.
assert_the_audit_override_binds_the_store() {
  local override="$WORK_DIR/secrets/openbao/docker-compose.openbao-audit.yml"
  [ -f "$override" ] || fail "no audit compose override was rendered at $override"
  grep -q "volumes: !override" "$override" ||
    fail "the audit override does not replace the volumes list"
  grep -qF "${AUDIT_STORE_DIR}/openbao:${OPENBAO_AUDIT_CONTAINER_DIR}" "$override" ||
    fail "the audit override does not bind ${AUDIT_STORE_DIR}/openbao"
  grep -qF "openbao-data:/openbao/file" "$override" ||
    fail "the audit override dropped OpenBao's storage mount"
  grep -qF "./openbao:/openbao/config:ro" "$override" ||
    fail "the audit override dropped OpenBao's configuration mount"
  pass "the rendered override binds the store and re-declares the other two mounts"
}

# The criterion this whole scenario exists for on this side: the running
# container's audit directory is backed by the store on the host.
assert_the_container_audit_dir_is_backed_by_the_store() {
  assert_equal "the container's ${OPENBAO_AUDIT_CONTAINER_DIR} is a bind mount of the store" \
    "bind ${AUDIT_STORE_DIR}/openbao" "$(container_audit_bind)"

  # `verify_audit_file` passed at init — the run would have aborted with
  # the audit-setup failure otherwise — and the device is writing into
  # the store now that the recreate has moved it.
  if grep -q "OpenBao audit backend setup failed" "$INIT_RAW_LOG"; then
    fail "init reported an OpenBao audit backend setup failure"
  fi
  pass "init's mandatory file audit device check passed"

  docker exec "${INSTANCE}-openbao" test -s "$OPENBAO_AUDIT_CONTAINER_LOG" ||
    fail "the OpenBao audit log is missing or empty at ${OPENBAO_AUDIT_CONTAINER_LOG}"
  sudo -n test -s "$AUDIT_STORE_DIR/openbao/audit.log" ||
    fail "the OpenBao audit log did not land in the store on the host"
  sudo -n grep -q '"type":"response"' "$AUDIT_STORE_DIR/openbao/audit.log" ||
    fail "the audit log in the store carries no OpenBao response entry"
  pass "the audit log OpenBao writes in the container is the file in the store on the host"
}

# The shared file-audit assertion every other lifecycle harness runs,
# unchanged, against a deployment whose audit device is on the store.
#
# That is the point of running it here: the helper reads the *container*
# path through `docker exec`, so a correct bind mount is transparent to
# it and it has to pass exactly as it does on a host still using the
# `openbao-audit` named volume.  A regression that moved the device
# somewhere the container does not see would fail here even though the
# host-side reads above still found a file.
#
# The entries it looks for — an `auth/approle/login` response and a
# `secret/data/...` read — are the two infra OpenBao Agent sidecars'.
# `init` starts them *after* the TLS recreate that moves the device
# (`apply_openbao_agent_compose_override`, phase 2 of the agent
# bring-up), so their traffic lands in the store rather than in the
# volume the device wrote to beforehand.  That holds for the first call
# alone: once a rotation or a move of the store has made another file
# the active one, the sidecars' entries are in the file left behind and
# the arm drives its own through `drive_fresh_audit_traffic` first.
assert_the_shared_audit_log_assertion_still_passes() {
  assert_openbao_audit_log "${INSTANCE}-openbao" "$OPENBAO_AUDIT_CONTAINER_LOG"
  pass "the shared OpenBao file-audit assertion passes over the store-backed device"
}

# ---------------------------------------------------------------------------
# Rotation of the file audit device by reopen-on-signal
# ---------------------------------------------------------------------------
#
# This is the one arm where bootroot's rotation meets the real writer
# and the real Docker.  It lives here rather than in
# `run-local-lifecycle.sh` because the rotation is conditional on
# `[registrar_endpoint] enabled = true`: only an endpoint-enabled host
# has `<audit_store_dir>/openbao` bind-mounted under the container's
# `/openbao/audit`, and this is the only scenario that provisions one.
# Everywhere else the device is still on the `openbao-audit` named
# volume, nothing on the host is there to rotate, and the rotation
# changes nothing.
#
# The rotation itself runs through the library's own code — an ignored
# unit test, driven the way `run-registrar-verbs-e2e.sh` drives its own
# — rather than through a shell reimplementation of the mechanism,
# because a shell rename-and-signal would prove the mechanism works and
# say nothing about the code that ships.  The test asserts the *signal*
# form was taken, so an image that stopped honouring `SIGHUP` fails this
# arm rather than quietly degrading it to the lossy fallback.

# One `OpenBao` API call with the root token, over the transitioned TLS
# listener, verified against the credential's own private bundle.
#
# Elevated because the bundle sits in a `0700` root-owned directory once
# a root-run `init` has created it, not because the bundle is protected
# material.  The token itself arrives through `-K`, whose file only root
# can read, so the argument list carries a path and never a credential.
openbao_api() {
  local method="$1" path="$2" data="${3:-}"
  local bundle="$INTERNAL_DIR/ca-bundle.pem"
  local -a args=(-sS -m 15 --cacert "$bundle" -X "$method")
  [ -z "$data" ] || args+=(-d "$data")
  sudo -n "$CURL_BIN" -K "$OPENBAO_CURL_CONFIG" "${args[@]}" \
    "https://localhost:${PORT_OPENBAO}/v1/${path}" 2>>"$RUN_LOG"
}

# The same call without a token, for the AppRole login, which mints one.
#
# Its body is read from standard input rather than taken as an argument,
# because the only call that needs this helper posts a `secret_id`, and
# that is as much a credential as the root token above.  `-d @-` is
# curl's spelling of "the body is on stdin"; the caller writes it with
# the `printf` builtin, which forks no process at all.
openbao_api_unauthed() {
  local method="$1" path="$2"
  local bundle="$INTERNAL_DIR/ca-bundle.pem"
  sudo -n "$CURL_BIN" -sS -m 15 --cacert "$bundle" -X "$method" -d @- \
    "https://localhost:${PORT_OPENBAO}/v1/${path}" 2>>"$RUN_LOG"
}

openbao_seal_state() {
  openbao_api GET "sys/seal-status" | jq -r '"\(.sealed) \(.initialized)"'
}

# The container's identity, as three values that all change on a
# restart: a rotation must move none of them.
openbao_container_state() {
  docker inspect "${INSTANCE}-openbao" \
    --format '{{.State.StartedAt}} {{.RestartCount}} {{.State.Pid}}' 2>>"$RUN_LOG"
}

# Builds the library test binary as the invoking user.
#
# `cargo` never runs under `sudo` here: a root-run build would leave
# root-owned artifacts under `target/` and break every later build in
# this checkout.  Only the finished binary crosses the boundary.
build_rotation_test_binary() {
  local manifest="$ARTIFACT_DIR/cargo-test-build.json"
  (cd "$ROOT_DIR" && cargo test --lib --no-run --message-format=json) \
    >"$manifest" 2>>"$RUN_LOG" ||
    fail "could not build the library test binary; see $RUN_LOG"
  ROTATION_TEST_BIN="$(jq -r 'select(.reason == "compiler-artifact")
      | select(any(.target.kind[]?; . == "lib"))
      | .executable // empty' "$manifest" | tail -n 1)"
  [ -n "$ROTATION_TEST_BIN" ] && [ -x "$ROTATION_TEST_BIN" ] ||
    fail "could not resolve the library test binary out of $manifest"
  pass "the library test binary is built as the invoking user"
}

# The active log becomes a generation and OpenBao creates a new one,
# without restarting, resealing or unsealing it, and its registration in
# `sys/audit` is untouched.
assert_the_device_rotates_by_reopen_on_signal() {
  local before after log="$ARTIFACT_DIR/audit-rotation-test.log"
  before="$(openbao_container_state)"
  [ -n "$before" ] || fail "could not read the OpenBao container's state"
  assert_equal "OpenBao is unsealed and initialised before the rotation" \
    "false true" "$(openbao_seal_state)"

  # `--exact` and the test's own name, so a rename here fails loudly
  # rather than silently selecting nothing and reporting success.
  set +e
  # Every value below is a path, including the token's: `sudo env` puts
  # its assignments in an argument list that `ps` shows to every user on
  # the host, so the test is told where to read the credential rather
  # than handed the credential.
  #
  # shellcheck disable=SC2024 # the redirect is the invoking user's own:
  # the log belongs beside this run's other artifacts, not to root.
  sudo -n env \
    BOOTROOT_OPENBAO_AUDIT_E2E_DIR="${AUDIT_STORE_DIR}/openbao" \
    BOOTROOT_OPENBAO_AUDIT_E2E_URL="https://localhost:${PORT_OPENBAO}" \
    BOOTROOT_OPENBAO_AUDIT_E2E_TOKEN_FILE="$OPENBAO_ROOT_TOKEN_FILE" \
    BOOTROOT_OPENBAO_AUDIT_E2E_CA_BUNDLE="$INTERNAL_DIR/ca-bundle.pem" \
    "$ROTATION_TEST_BIN" \
    registrar::openbao_audit::tests::a_live_openbao_audit_device_rotates_by_reopen_on_signal \
    --exact --ignored --nocapture >"$log" 2>&1
  local status=$?
  set -e
  [ "$status" -eq 0 ] ||
    fail "the reopen-on-signal rotation of the live audit device failed; see $log"
  grep -q "1 passed" "$log" ||
    fail "the reopen-on-signal rotation test selected no test; see $log"
  pass "bootroot rotated the live audit device by reopen-on-signal, losing no record, and \
sys/audit is unchanged"

  after="$(openbao_container_state)"
  assert_equal "OpenBao was neither restarted nor replaced by the rotation" \
    "$before" "$after"
  assert_equal "OpenBao is still unsealed and initialised after the rotation" \
    "false true" "$(openbao_seal_state)"
}

# The audited path of the record driven before the rotation.
LOSSLESS_MARKER_BEFORE=""

# Drives one request whose audited path is unique to this run, so that
# "the rotation lost nothing" can be asserted against a *record* rather
# than against a byte count that a coincidence could satisfy.
drive_a_marker_record_before_the_rotation() {
  LOSSLESS_MARKER_BEFORE="lossless-$(od -An -N8 -tx1 </dev/urandom | tr -d ' \n')"
  openbao_api GET "secret/data/${LOSSLESS_MARKER_BEFORE}" >/dev/null ||
    fail "could not drive the pre-rotation marker record"
  sudo -n grep -qF "$LOSSLESS_MARKER_BEFORE" "${AUDIT_STORE_DIR}/openbao/audit.log" ||
    fail "the pre-rotation marker record never reached the active log"
  pass "a marker record was driven into the active log before the rotation"
}

# The rotation loses no record: the entry driven before it is in the
# generation and nowhere else, the entry driven after it is in the new
# active log and nowhere else, and neither is duplicated.
#
# The rename-and-reopen mechanism copies nothing, so the generation *is*
# the file the pre-rotation entry was written to.  A copy-and-truncate
# fallback would have destroyed whatever landed while the copy ran, which
# is the property this arm exists to pin.
#
# `sudo -n bash -c` rather than a bare `sudo -n grep`: the glob has to be
# expanded by the elevated shell, since the store directory is root-owned
# and `0700` and the invoking user cannot list it.
assert_the_rotation_lost_no_record() {
  local dir="${AUDIT_STORE_DIR}/openbao" after hits
  after="lossless-$(od -An -N8 -tx1 </dev/urandom | tr -d ' \n')"
  openbao_api GET "secret/data/${after}" >/dev/null ||
    fail "could not drive the post-rotation marker record"

  hits="$(sudo -n bash -c \
    "grep -lF '${LOSSLESS_MARKER_BEFORE}' '${dir}'/audit-*.log '${dir}/audit.log' 2>/dev/null | wc -l" |
    tr -d ' ')"
  assert_equal "the record driven before the rotation survives in exactly one file" \
    "1" "$hits"
  if sudo -n grep -qF "$LOSSLESS_MARKER_BEFORE" "${dir}/audit.log"; then
    fail "the pre-rotation record is in the new active log, so the generation is not the file \
it was written to"
  fi
  sudo -n bash -c "grep -qF '${LOSSLESS_MARKER_BEFORE}' '${dir}'/audit-*.log" ||
    fail "the record driven before the rotation is in no generation: the rotation lost it"

  hits="$(sudo -n bash -c \
    "grep -lF '${after}' '${dir}'/audit-*.log '${dir}/audit.log' 2>/dev/null | wc -l" |
    tr -d ' ')"
  assert_equal "the record driven after the rotation appears in exactly one file" "1" "$hits"
  sudo -n grep -qF "$after" "${dir}/audit.log" ||
    fail "the record driven after the rotation did not reach the new active log"

  pass "the rotation lost no record: the pre-rotation entry is in the generation, the \
post-rotation entry is in the new active log, and neither is duplicated"
}

# A fresh AppRole login and a fresh KV read, driven against whatever
# file the device is writing to now.
#
# The shared assertion reads the device's *active* log, so it passes
# exactly when the entries it looks for were written since that file
# became the active one -- which both a rotation and a move of the store
# invalidate.  Waiting for the two infra sidecars to supply them again
# is not an option in either case: an OpenBao Agent that already holds a
# token renews it rather than logging in afresh, and the token survives
# the container being replaced because it lives in OpenBao's storage, so
# no `auth/approle/login` need ever follow.  The role is therefore this
# run's own, and the login is traffic the calling arm caused.
#
# `slug` names the arm in the role and in the KV path it reads, so two
# arms driving traffic in one run do not share either; `occasion` is the
# phrase the two reported assertions end with.
drive_fresh_audit_traffic() {
  local slug="$1" occasion="$2"
  local role="audit-${slug}-${RUN_TOKEN}" role_id secret_id status
  openbao_api POST "auth/approle/role/${role}" \
    '{"token_policies":"default","token_ttl":"60s"}' >/dev/null ||
    fail "could not create the AppRole for the traffic driven ${occasion}"
  role_id="$(openbao_api GET "auth/approle/role/${role}/role-id" |
    jq -r '.data.role_id // empty')"
  secret_id="$(openbao_api POST "auth/approle/role/${role}/secret-id" '{}' |
    jq -r '.data.secret_id // empty')"
  [ -n "$role_id" ] && [ -n "$secret_id" ] ||
    fail "could not mint an AppRole credential for the traffic driven ${occasion}"

  status="$(printf '{"role_id":"%s","secret_id":"%s"}' "$role_id" "$secret_id" |
    openbao_api_unauthed POST "auth/approle/login" |
    jq -r 'if .auth.client_token then "ok" else "no-token" end')"
  assert_equal "an AppRole login succeeds ${occasion}" "ok" "$status"

  # A read of a path that need not exist: the device records the
  # request either way, which is what the assertion below looks for, and
  # inventing a KV secret here would be this arm writing state it does
  # not own.
  openbao_api GET "secret/data/bootroot-audit-${slug}" >/dev/null ||
    fail "the KV read driven ${occasion} raised"
  pass "a fresh AppRole login and KV read were driven ${occasion}"
}

# The active log OpenBao created after the reopen is a fresh file it
# appends to from offset zero, not one it went on writing at its old
# offset into a sparse hole.  Established against the pinned image
# rather than assumed, because "the signal was honoured" and "the new
# file is written correctly" are two claims and only the first is what
# the reopen evidence establishes.
#
# It also rests on the daemon and the container seeing one filesystem,
# which a Linux bind mount is.  That is moot for this harness, which
# already needs passwordless sudo and so does not run on a macOS
# developer machine at all.
assert_the_rotated_active_log_begins_at_offset_zero() {
  local host_log="${AUDIT_STORE_DIR}/openbao/audit.log" first
  sudo -n test -s "$host_log" ||
    fail "the rotated active log took no writes at all"
  first="$(sudo -n head -c 1 "$host_log" | od -An -tu1 | tr -d '[:space:]')"
  [ "$first" != "0" ] ||
    fail "the rotated active log begins with a NUL byte: the device is not appending"
  sudo -n head -n 1 "$host_log" | jq -e . >/dev/null 2>>"$RUN_LOG" ||
    fail "the rotated active log's first line is not a well-formed JSON record"
  pass "the rotated active log begins at offset 0 with a well-formed record"
}

# Waits for a file on the reserve to grow past a size the caller
# recorded earlier.
#
# The audit device appends, so a restarted container inherits every
# entry the previous one wrote and the shared assertion would pass on
# those alone.  What has to be shown after a restart is that the *new*
# container is writing into the mounted reserve, which is growth and
# nothing else.  Bounded, and it reports rather than decides: the caller
# asserts on the two sizes so a failure names them.
wait_for_file_growth() {
  local path="$1" floor="$2" attempt=0
  while [ "$attempt" -lt "$AUDIT_ENTRIES_ATTEMPTS" ]; do
    if [ "$(sudo -n stat -c %s "$path" 2>/dev/null || echo 0)" -gt "$floor" ]; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep "$AUDIT_ENTRIES_DELAY_SECS"
  done
  return 0
}

# The store's device number, which is the mounted filesystem's once the
# reserve is up and the directory underneath it otherwise.
store_device() {
  sudo -n stat -c %d "$1"
}

# The audit device the running OpenBao container is bound to, as
# `docker inspect` reports it.
container_audit_bind() {
  docker inspect "${INSTANCE}-openbao" \
    --format "{{range .Mounts}}{{if eq .Destination \"${OPENBAO_AUDIT_CONTAINER_DIR}\"}}{{.Type}} {{.Source}}{{end}}{{end}}" \
    2>>"$RUN_LOG" || true
}

# A unit-name list from `systemctl show`, folded to a form the rendered
# name can be compared against.
#
# The reserve's mount unit is named for its path, so every `-` in that
# path is `\x2d` in the unit name -- and a name carrying a backslash is
# one `systemctl show` considers to need quoting.  It prints it as a
# double-quoted word with each backslash doubled, so the raw name this
# run rendered is a substring of neither `After=` nor `Wants=` as they
# come back.  Both sides drop their quotes and backslashes here rather
# than this script reimplementing systemd's quoting rules to rebuild the
# printed spelling; what is left still names the unit unambiguously.
fold_unit_list() {
  local folded="${1//\\/}"
  printf '%s' "${folded//\"/}"
}

# Everything the reserve is for on the deployment's side: a live OpenBao
# writing its mandatory file audit device into a mounted one.
#
# The activation section above proves the reserve itself -- that the
# rendered commands bring it up, that the re-run reports **enforced**,
# that a second run reformats nothing and that a write past it stops at
# the reserve.  Every assertion there runs against a store with no
# deployment on it and a deliberately dead OpenBao URL, so what none of
# them says is whether a container can be brought up on one at all.
# That is a different set of failures: the bind source is a directory
# inside a mounted filesystem whose root the *operator* chmods by hand,
# its `openbao/` is root-owned `0700` until the compose entrypoint
# chowns it, an unprivileged `bootroot infra up` has to accept the store
# it finds there, and the mount has to still be under the container
# after the stack is restarted over it.
#
# Run last, and deliberately.  It moves this deployment's audit device
# off the `directory`-mode store every assertion above is about, and it
# ends by filling the reserve out from under a running container.
# Nothing after it would still hold, and nothing is scheduled after it.
#
# Skipped whole on a host that cannot carry an activated reserve, on the
# same probe the activation section uses: the assertions here are about
# a deployment on a real loop device, and there is no weaker form of
# them worth running.
assert_the_deployment_runs_on_a_mounted_reserve() {
  local config log store image unit reserve=16777216
  if ! reserve_activation_is_possible; then
    log "this host has no systemd, loop device or mkfs.ext4; the mounted-reserve deployment section is skipped"
    return 0
  fi
  store="$AUDIT_STORE_BASE/reserve-deployed"
  image="${store}.img"
  config="$WORK_DIR/operator-agent-deployed.toml"
  log="$ARTIFACT_DIR/init-reserve-deployed.log"
  write_reserve_agent_config "$config" "$store" "$reserve"

  # The override on disk names the `directory`-mode store this
  # deployment was initialised against, and `plan_audit_store` refuses a
  # run whose `--agent-config` resolves another one -- which is the
  # check that keeps a moved store from being provisioned quietly.
  # Removing it here is the harness stating that this is not a
  # relocation: the device moves to an *empty* reserve, and the old
  # store keeps every byte it had, which is what the reads at the end
  # confirm.  Carrying records across belongs to the relocation issue.
  remove_rendered_audit_override

  if run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "$RESERVE_DEAD_OPENBAO_URL" \
    --agent-config "$config" \
    </dev/null >"$log" 2>&1; then
    fail "the first run reported success on an unactivated host; see $log"
  fi
  grep -q "provisioned, not activated" "$log" ||
    fail "the first run did not report provisioned, not activated; see $log"

  unit="$(basename "$(find "$WORK_DIR/audit-store" -maxdepth 1 -name '*.mount' -print -quit)")" ||
    unit=""
  [ -n "$unit" ] || fail "no .mount unit was rendered under $WORK_DIR/audit-store"
  # Recorded before the first host-changing command, so cleanup can undo
  # whatever the sequence got through.
  RESERVE_STORE_DIR="$store"
  RESERVE_IMAGE="$image"
  RESERVE_UNIT_NAME="$unit"

  run_rendered_phase_two "$log"
  if run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "$RESERVE_DEAD_OPENBAO_URL" \
    --agent-config "$config" \
    </dev/null >"${log}.2" 2>&1; then
    : # The dead URL stops this run at the OpenBao health check, which
      # is the first step after the audit store that reaches the
      # network.  The outcome is printed before it.
  fi
  grep -q "enforced (filesystem)" "${log}.2" ||
    fail "the run over the activated reserve did not report enforced; see ${log}.2"
  pass "the reserve the deployment will use reports enforced"

  # The ordering the automatic boot path rests on, read back off the
  # unit systemd actually loaded rather than off the file phase 2
  # installed.  `Wants=` plus `After=` and nothing stronger is the whole
  # relation: a failed mount job does not stop `docker.service`, which
  # is the residual both manuals state and which this asserts rather
  # than quietly strengthens.
  if sudo -n systemctl cat docker.service >/dev/null 2>&1; then
    local folded_unit
    folded_unit="$(fold_unit_list "$unit")"
    case "$(fold_unit_list "$(sudo -n systemctl show docker.service -p After --value)")" in
      *"$folded_unit"*) pass "the loaded docker.service orders itself after the mount unit" ;;
      *) fail "docker.service does not order itself after $unit" ;;
    esac
    case "$(fold_unit_list "$(sudo -n systemctl show docker.service -p Wants --value)")" in
      *"$folded_unit"*) pass "the loaded docker.service wants the mount unit" ;;
      *) fail "docker.service does not want $unit" ;;
    esac
    case "$(fold_unit_list "$(sudo -n systemctl show docker.service -p Requires --value)")" in
      *"$folded_unit"*) fail "docker.service carries a hard relation to $unit" ;;
      *) pass "the loaded docker.service carries no hard relation to the mount unit" ;;
    esac
  else
    log "docker.service is not a systemd unit on this host; the loaded-ordering assertion is skipped"
  fi

  # The bring-up that moves the device.  Unprivileged, like every other
  # `infra up` in this scenario: it reads the bind source back out of
  # the override this run rendered and checks the store directory that
  # names -- which, with the reserve up, is the *mounted filesystem's
  # root*.  `mkfs.ext4` leaves that root at `0755` and the store
  # contract is `0700`, so this is also where the rendered `chmod 0700`
  # on `audit_store_dir` earns its place: without it the bring-up
  # refuses the store the run it followed had just reported enforced.
  log "bringing the stack up on the mounted reserve"
  run_bootroot infra up \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --openbao-url "https://localhost:${PORT_OPENBAO}" \
    >>"$RUN_LOG" 2>&1 || fail "infra up failed over the mounted reserve; see $RUN_LOG"
  pass "an unprivileged bring-up accepted the mounted reserve as the store"

  assert_equal "the container's ${OPENBAO_AUDIT_CONTAINER_DIR} is a bind mount of the mounted reserve" \
    "bind ${store}/openbao" "$(container_audit_bind)"

  local store_dev
  store_dev="$(store_device "$store")"
  assert_equal "records/ sits on the mounted reserve" \
    "$store_dev" "$(store_device "$store/records")"
  assert_equal "openbao/ sits on the mounted reserve" \
    "$store_dev" "$(store_device "$store/openbao")"

  # The device is writing to a file that did not exist a moment ago, so
  # the two entries the shared assertion looks for have to be driven
  # rather than waited for -- see `drive_fresh_audit_traffic`.
  drive_fresh_audit_traffic reserve-move "over the moved audit device"
  sudo -n test -s "$store/openbao/audit.log" ||
    fail "the OpenBao audit log did not land on the mounted reserve"
  assert_equal "the audit log itself sits on the mounted reserve" \
    "$store_dev" "$(store_device "$store/openbao/audit.log")"
  assert_openbao_audit_log "${INSTANCE}-openbao" "$OPENBAO_AUDIT_CONTAINER_LOG"
  pass "the shared OpenBao file-audit assertion passes over a device on the mounted reserve"

  # The restart.  `stop` and then the product's own bring-up rather than
  # `docker restart`: what has to survive is the stack being taken down
  # and put back over a mount nothing in Compose knows about, and the
  # bring-up is the surface an operator would use.  OpenBao seals when
  # it stops and `infra up` unseals it again, and the traffic driven
  # below then fills the device a second time.
  local started_before started_after log_before
  started_before="$(docker inspect "${INSTANCE}-openbao" --format '{{.State.StartedAt}}' 2>>"$RUN_LOG" || true)"
  [ -n "$started_before" ] || fail "could not read the OpenBao container's start time"
  log_before="$(sudo -n stat -c %s "$store/openbao/audit.log")"
  instance_compose stop >>"$RUN_LOG" 2>&1 || fail "could not stop the stack over the mounted reserve"
  log "bringing the stack back up over the mounted reserve"
  run_bootroot infra up \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --openbao-url "https://localhost:${PORT_OPENBAO}" \
    >>"$RUN_LOG" 2>&1 || fail "infra up failed after the stack restart; see $RUN_LOG"
  started_after="$(docker inspect "${INSTANCE}-openbao" --format '{{.State.StartedAt}}' 2>>"$RUN_LOG" || true)"
  if [ "$started_before" = "$started_after" ]; then
    fail "the OpenBao container was not restarted; start time stayed at ${started_before}"
  fi
  pass "the stack was stopped and brought back up over the mounted reserve"

  assert_equal "the mount unit is still active after the restart" \
    "ActiveState=active" "$(sudo -n systemctl show -p ActiveState "$unit")"
  assert_equal "the restarted container's ${OPENBAO_AUDIT_CONTAINER_DIR} is still the mounted reserve" \
    "bind ${store}/openbao" "$(container_audit_bind)"
  assert_equal "the store is still the mounted filesystem after the restart" \
    "$store_dev" "$(store_device "$store")"
  drive_fresh_audit_traffic reserve-restart "over the restarted container"
  wait_for_file_growth "$store/openbao/audit.log" "$log_before"
  assert_equal "the restarted container is writing into the mounted reserve" "yes" \
    "$([ "$(sudo -n stat -c %s "$store/openbao/audit.log")" -gt "$log_before" ] && echo yes || echo no)"
  assert_openbao_audit_log "${INSTANCE}-openbao" "$OPENBAO_AUDIT_CONTAINER_LOG"
  pass "the shared file-audit assertion passes again after the stack restart"

  # The regression an owner-comparing implementation fails, end to end:
  # the compose entrypoint has chowned `/openbao/audit` to the container's
  # own user by now, so `openbao/` on the host is no longer root's --
  # and a run over it must still report **enforced**, because its owner
  # is deliberately not compared.
  if run_bootroot_as_root init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "$RESERVE_DEAD_OPENBAO_URL" \
    --agent-config "$config" \
    </dev/null >"${log}.3" 2>&1; then
    :
  fi
  grep -q "enforced (filesystem)" "${log}.3" ||
    fail "a run over a container-owned openbao/ did not report enforced; see ${log}.3"
  grep -q "ownership is not verified" "${log}.3" ||
    fail "the enforced outcome does not carry the openbao/ ownership caveat"
  pass "the reserve is still enforced once the container owns openbao/"

  # The ceiling, against the deployment rather than against an empty
  # reserve: the filesystem the running container's audit device sits on
  # is the reserve, so a write past it fails there and the host's root
  # filesystem is not what absorbs it.  Last of all, because it fills
  # the device OpenBao is required to be able to write.
  local root_before root_after
  root_before="$(df -P -k / | awk 'NR==2 {print $4}')"
  if sudo_to_log dd if=/dev/zero of="$store/records/fill" bs=1M count=64; then
    fail "a write of four times the reserve succeeded under the deployment"
  fi
  assert_equal "the overflowing file stopped inside the deployed reserve" "yes" \
    "$([ "$(sudo -n stat -c %s "$store/records/fill")" -lt "$reserve" ] && echo yes || echo no)"
  root_after="$(df -P -k / | awk 'NR==2 {print $4}')"
  assert_equal "the root filesystem did not absorb the overflow" "yes" \
    "$([ "$(( root_before - root_after ))" -lt 8192 ] && echo yes || echo no)"
  sudo -n rm -f "$store/records/fill"

  # The `directory`-mode store this deployment was initialised against
  # is untouched by all of the above: the device moved, and nothing
  # carried or removed what was already there.
  sudo -n test -s "$AUDIT_STORE_DIR/openbao/audit.log" ||
    fail "the directory-mode store lost the audit log it already held"
  pass "the store the device moved off still holds every byte it had"

  # The activation stays on the host until cleanup: the container is
  # bound into the mounted store and the unmount would be refused while
  # it runs.  `cleanup` tears the instance down first and then calls
  # `remove_reserve_activation`, which the globals above are set for.
}

# The alias is why the ACME challenge above could resolve at all.
# Asserted directly so a future change that drops it fails with the
# reason rather than as an unexplained issuance timeout.
assert_the_responder_answers_to_the_internal_san() {
  local aliases
  aliases="$(docker inspect "${INSTANCE}-http01" \
    --format '{{range .NetworkSettings.Networks}}{{range .Aliases}}{{println .}}{{end}}{{end}}' \
    2>>"$RUN_LOG" || true)"
  grep -qx "$INTERNAL_SAN" <<<"$aliases" ||
    fail "the responder does not answer to ${INTERNAL_SAN}; aliases: $(tr '\n' ' ' <<<"$aliases")"
  pass "the responder answers to the internal SAN"
}

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

# The left-hand name is the artifact this scenario's CI step reads back
# on failure; the right-hand one is the container the compose file
# actually names.  They differ for step-ca — the service is `step-ca`
# and its `container_name` is `${INSTANCE}-ca` — and a log named after
# the service alone collected nothing but docker's `No such container`
# for exactly the run that needed it.
#
# The two infra OpenBao Agent sidecars are here because their failures
# are silent from the outside: the containers stay up and retry, and
# only their logs say whether the auto-auth login and the template
# renders they exist to perform are landing.
capture_artifacts() {
  local pair name container
  for pair in \
    openbao:openbao \
    step-ca:ca \
    http01:http01 \
    postgres:postgres \
    openbao-agent-stepca:openbao-agent-stepca \
    openbao-agent-responder:openbao-agent-responder; do
    name="${pair%%:*}"
    container="${INSTANCE}-${pair#*:}"
    docker logs "$container" >"$ARTIFACT_DIR/${name}.log" 2>&1 || true
  done
  [ -f "$WORK_DIR/state.json" ] && cp "$WORK_DIR/state.json" "$ARTIFACT_DIR/state.json" || true
  # Elevated, and re-owned to the invoking user afterwards: a root-owned
  # file left in the artifact directory outlives this run and the user
  # who has to read it cannot remove it.
  # Reached by the cleanup of a run that failed its prerequisites too,
  # where sudo has already been established as unavailable; its
  # complaint goes to the run log rather than on top of the refusal that
  # already explained itself.
  if sudo -n test -f "$INTERNAL_DIR/agent.toml" 2>>"$RUN_LOG"; then
    sudo -n cp "$INTERNAL_DIR/agent.toml" "$ARTIFACT_DIR/registrar-internal-agent.toml" &&
      sudo -n chown "$(id -u):$(id -g)" "$ARTIFACT_DIR/registrar-internal-agent.toml" || true
  fi
  return 0
}

teardown_instance() {
  local id ids status=0
  if [ -n "$WORK_DIR" ] && [ -f "$WORK_DIR/$COMPOSE_FILE_NAME" ]; then
    instance_compose down -v --remove-orphans >>"$RUN_LOG" 2>&1 || status=1
  fi
  if ids="$(docker ps -aq --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do
      docker rm -f "$id" >>"$RUN_LOG" 2>&1 || status=1
    done
  else
    status=1
  fi
  if ids="$(docker volume ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do
      docker volume rm -f "$id" >>"$RUN_LOG" 2>&1 || status=1
    done
  else
    status=1
  fi
  if ids="$(docker network ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do
      docker network rm "$id" >>"$RUN_LOG" 2>&1 || status=1
    done
  else
    status=1
  fi
  return "$status"
}

remove_run_root() {
  [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ] || return 0
  if rm -rf "$RUN_ROOT" 2>/dev/null; then
    return 0
  fi
  # A container may have left material under `secrets/` owned by another
  # uid.  Re-own it through a throwaway container rather than reaching
  # for host privileges.
  local helper
  helper="$(docker inspect --format '{{.Config.Image}}' "${INSTANCE}-openbao" 2>/dev/null || true)"
  if [ -n "$helper" ]; then
    docker run --rm --user root --entrypoint sh -v "${RUN_ROOT}:/mnt" "$helper" \
      -c "chown -R $(id -u):$(id -g) /mnt" >/dev/null 2>&1 || true
  fi
  rm -rf "$RUN_ROOT" 2>/dev/null || true
  [ -d "$RUN_ROOT" ] || return 0
  # What is left is this run's own root-owned output: the `0700`
  # internal directory and the five protected files a root `init`
  # published there.  The path is this run's `mktemp -d`, never an
  # operator's, and the containers that could still be holding it open
  # are gone by the time cleanup reaches here.
  sudo -n rm -rf "$RUN_ROOT" 2>>"$RUN_LOG" || true
}

# The store is root-owned `0700`, so its removal goes through the same
# `sudo -n` the rest of this scenario already requires.
remove_audit_store_base() {
  [ -n "$AUDIT_STORE_BASE" ] && [ -d "$AUDIT_STORE_BASE" ] || return 0
  if rm -rf "$AUDIT_STORE_BASE" 2>/dev/null; then
    return 0
  fi
  # What is left is this run's own root-owned store.  The path is this
  # run's `mktemp -d`, never an operator's.
  sudo -n rm -rf "$AUDIT_STORE_BASE" 2>>"$RUN_LOG" || true
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  capture_artifacts
  teardown_instance || {
    echo "[registrar-internal-init][cleanup] teardown failed; see ${RUN_LOG}" >&2
    cleanup_status=1
  }
  [ "$HTTP01_IMAGE_BUILT" -eq 1 ] &&
    { docker image rm -f "$HTTP01_IMAGE" >>"$RUN_LOG" 2>&1 || true; }
  # Before the store base is removed: an activated reserve is a mount
  # inside it, and `rm -rf` would descend into the mounted filesystem
  # rather than into the directory it is covering.
  remove_reserve_activation
  remove_run_root
  remove_audit_store_base
  report_project_leftovers "$INSTANCE" "registrar-internal-init cleanup" || cleanup_status=1
  if [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ]; then
    echo "[registrar-internal-init][cleanup] run root survived: ${RUN_ROOT}" >&2
    cleanup_status=1
  fi
  if [ -n "$AUDIT_STORE_BASE" ] && [ -d "$AUDIT_STORE_BASE" ]; then
    echo "[registrar-internal-init][cleanup] audit store base survived: ${AUDIT_STORE_BASE}" >&2
    cleanup_status=1
  fi
  exit_with_cleanup_status "$status" "$cleanup_status"
}

main() {
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  log_phase "startup"
  trap cleanup EXIT

  ensure_prerequisites
  log "instance: ${INSTANCE}"
  # The instance name is this run's alone, so anything already carrying
  # its project label is wreckage from a crashed run that shared the
  # token — and installing over it would inherit that state rather than
  # test a fresh one.
  assert_no_project_leftovers "$INSTANCE" "registrar-internal-init start of run"

  log_phase "prepare"
  create_run_root
  create_audit_store_base
  build_responder_image
  prepull_third_party_images

  log_phase "install"
  allocate_ports
  install_infra
  wait_for_postgres_admin
  wait_for_openbao_listening

  log_phase "seed-predicate"
  seed_registrar_endpoint_predicate
  seed_agent_configuration

  log_phase "refuse-unprivileged"
  assert_an_unprivileged_init_is_refused

  log_phase "assert-filesystem-mode"
  assert_filesystem_mode_stops_before_it_touches_the_host
  assert_the_rendered_steps_activate_the_reserve

  log_phase "init"
  run_init

  log_phase "assert-material"
  assert_material_is_complete_and_restrictive
  assert_generated_config_is_the_internal_one
  assert_leaf_carries_the_fixed_san
  assert_the_responder_answers_to_the_internal_san
  assert_the_infra_agent_tree_belongs_to_its_sidecars
  assert_the_infra_agents_are_generated_for_tls

  log_phase "assert-audit-store"
  assert_audit_store_is_provisioned
  assert_the_directory_mode_outcome_is_a_success
  assert_the_audit_override_binds_the_store
  assert_the_container_audit_dir_is_backed_by_the_store

  log_phase "assert-listener"
  assert_state_url_moved_to_https
  assert_listener_serves_tls
  assert_no_listener_client_cert_options

  log_phase "assert-login"
  assert_certificate_login_succeeds
  assert_login_without_the_certificate_is_refused

  # Last, because it re-runs the two ownership assertions against a
  # deployment a later command has passed over: the protected five must
  # still be root's, and the sidecar tree must still be the sweep's to
  # repair.  A sweep that swept everything would fail the first; a
  # sweep narrowed too far would fail the second.
  log_phase "assert-sweep"
  run_infra_up_over_the_initialised_deployment
  assert_material_is_complete_and_restrictive
  assert_the_infra_agent_tree_belongs_to_its_sidecars
  # The unprivileged bring-up selected the audit override and checked
  # the store directory it names — the one check a process that cannot
  # descend into a root-owned `0700` store can make — so the device is
  # still on the store afterwards.
  assert_audit_store_is_provisioned
  assert_the_container_audit_dir_is_backed_by_the_store
  # Last of all, and deliberately: the shared assertion wants traffic
  # from both infra agents in the log, and this is the point in the run
  # with the most of it behind us — the bring-up above recreated the
  # stack and both sidecars re-authenticated against the store-backed
  # device.
  assert_the_shared_audit_log_assertion_still_passes

  # The device this run has been filling is then rotated in place.
  # Deliberately after the assertion above, so that one still runs
  # against a log no rotation has touched and this one runs against a
  # log a rotation has emptied.
  log_phase "assert-audit-rotation"
  build_rotation_test_binary
  drive_a_marker_record_before_the_rotation
  assert_the_device_rotates_by_reopen_on_signal
  assert_the_rotation_lost_no_record
  drive_fresh_audit_traffic rotation "immediately after the rotation"
  assert_the_rotated_active_log_begins_at_offset_zero
  # The same shared assertion, unmodified, over the rotated deployment.
  assert_the_shared_audit_log_assertion_still_passes

  # Last, and after everything the `directory`-mode deployment asserts:
  # this phase moves the audit device onto a mounted reserve and ends by
  # filling that reserve out from under the container, so no assertion
  # above would still hold once it has run.
  log_phase "assert-filesystem-deployment"
  assert_the_deployment_runs_on_a_mounted_reserve

  # This intentionally leaves the deployment at the ordinary init
  # phase-two boundary, so it follows every assertion that needs the
  # activated reserve above.
  log_phase "assert-reinit-filesystem-boundary"
  assert_reinit_defers_a_fresh_filesystem_reserve_to_init

  log_phase "done"
  log "endpoint-enabled init checks passed"
  echo "[registrar-internal-init] artifacts: $ARTIFACT_DIR"
}

main "$@"
