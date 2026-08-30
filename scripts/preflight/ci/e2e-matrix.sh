#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
SKIP_HOSTS=0
FRESH_SECRETS=0
SECRETS_BACKUP_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/preflight/ci/e2e-matrix.sh [--skip-hosts] [--fresh-secrets]

Runs the same Docker E2E matrix steps used in CI:
1) local lifecycle (no-hosts)
2) local lifecycle (hosts)
3) remote lifecycle (no-hosts)
4) remote lifecycle (hosts)
5) rotation/recovery full matrix
6) reinit recovery
7) step-ca certificate SANs
8) OpenBao TLS transition with no compose delta
9) OpenBao TLS re-issuance after secrets/ is re-owned
10) two co-located instances stay independent
11) registrar mint/deregister verbs against a live OpenBao
12) the bootroot-internal credential's auth/cert contract against a live TLS OpenBao
13) bootroot init on an endpoint-enabled loopback host, end to end
14) registrar credential-boundary red-team gate

Step 13 runs `bootroot init` as root through `sudo -n`, because an
endpoint-enabled `init` publishes the bootroot-internal credential root-owned
and refuses to publish it otherwise. Passwordless sudo is a prerequisite of
this matrix; --skip-hosts does not stand in for it.

Options:
  --skip-hosts  Skip hosts steps (they alone need write access to /etc/hosts;
                step 13 still needs sudo -n)
  --fresh-secrets   Temporarily replace ./secrets with a clean directory and restore it on exit
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-hosts)
      SKIP_HOSTS=1
      shift
      ;;
    --fresh-secrets)
      FRESH_SECRETS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

restore_secrets() {
  if [ -n "$SECRETS_BACKUP_DIR" ] && [ -d "$SECRETS_BACKUP_DIR/secrets" ]; then
    rm -rf "$ROOT_DIR/secrets"
    mv "$SECRETS_BACKUP_DIR/secrets" "$ROOT_DIR/secrets"
    rm -rf "$SECRETS_BACKUP_DIR"
  fi
}

if [ "$FRESH_SECRETS" -eq 1 ]; then
  SECRETS_BACKUP_DIR="/tmp/bootroot-secrets-backup-${RUN_ID}"
  mkdir -p "$SECRETS_BACKUP_DIR"
  if [ -d "$ROOT_DIR/secrets" ]; then
    mv "$ROOT_DIR/secrets" "$SECRETS_BACKUP_DIR/secrets"
  fi
  mkdir -p "$ROOT_DIR/secrets"
  chmod 700 "$ROOT_DIR/secrets" || true
  trap restore_secrets EXIT
fi

echo "[ci-local-e2e] run id: $RUN_ID"
echo "[ci-local-e2e] building bootroot binaries"
cargo build --bin bootroot --bin bootroot-remote --bin bootroot-agent

# The local lifecycle runs the daemon-only model: every service agent
# is a host bootroot-agent process whose fast-poll loop (default
# fast_poll_interval = 30s) propagates rotated secrets.  Verify
# retries are sized to cover a full poll interval on slow runners.
echo "[ci-local-e2e] run local lifecycle (no-hosts)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-local-no-hosts-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-local-no-hosts-${RUN_ID}" \
RESOLUTION_MODE="no-hosts" \
SECRETS_DIR="$ROOT_DIR/secrets" \
TIMEOUT_SECS=180 \
INFRA_UP_ATTEMPTS=12 \
INFRA_UP_DELAY_SECS=10 \
VERIFY_ATTEMPTS=20 \
VERIFY_DELAY_SECS=4 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
"$ROOT_DIR/scripts/impl/run-local-lifecycle.sh"

if [ "$SKIP_HOSTS" -eq 0 ]; then
  echo "[ci-local-e2e] run local lifecycle (hosts)"
  ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-local-hosts-${RUN_ID}" \
  PROJECT_NAME="bootroot-e2e-ci-local-hosts-${RUN_ID}" \
  RESOLUTION_MODE="hosts" \
  SECRETS_DIR="$ROOT_DIR/secrets" \
  TIMEOUT_SECS=180 \
  INFRA_UP_ATTEMPTS=12 \
  INFRA_UP_DELAY_SECS=10 \
  VERIFY_ATTEMPTS=20 \
  VERIFY_DELAY_SECS=4 \
  BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
  BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
  BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
  "$ROOT_DIR/scripts/impl/run-local-lifecycle.sh"
else
  echo "[ci-local-e2e] skip local lifecycle (hosts)"
fi

echo "[ci-local-e2e] run remote lifecycle (no-hosts)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-remote-no-hosts-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-remote-no-hosts-${RUN_ID}" \
RESOLUTION_MODE="no-hosts" \
SECRETS_DIR="$ROOT_DIR/secrets" \
TIMEOUT_SECS=120 \
INFRA_UP_ATTEMPTS=12 \
INFRA_UP_DELAY_SECS=10 \
VERIFY_ATTEMPTS=5 \
VERIFY_DELAY_SECS=5 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
"$ROOT_DIR/scripts/impl/run-remote-lifecycle.sh"

if [ "$SKIP_HOSTS" -eq 0 ]; then
  echo "[ci-local-e2e] run remote lifecycle (hosts)"
  ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-remote-hosts-${RUN_ID}" \
  PROJECT_NAME="bootroot-e2e-ci-remote-hosts-${RUN_ID}" \
  RESOLUTION_MODE="hosts" \
  SECRETS_DIR="$ROOT_DIR/secrets" \
  TIMEOUT_SECS=120 \
  INFRA_UP_ATTEMPTS=12 \
  INFRA_UP_DELAY_SECS=10 \
  VERIFY_ATTEMPTS=5 \
  VERIFY_DELAY_SECS=5 \
  BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
  BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
  BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
  "$ROOT_DIR/scripts/impl/run-remote-lifecycle.sh"
else
  echo "[ci-local-e2e] skip remote lifecycle (hosts)"
fi

echo "[ci-local-e2e] run rotation/recovery full matrix"
SCENARIO_FILE="$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json" \
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-rotation-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-rotation-${RUN_ID}" \
ROTATION_ITEMS="secret_id,eab,responder_hmac,trust_sync" \
TIMEOUT_SECS=90 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
"$ROOT_DIR/scripts/impl/run-rotation-recovery.sh"

echo "[ci-local-e2e] run reinit recovery (issue #600)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-reinit-recovery-${RUN_ID}" \
COMPOSE_PROJECT_NAME="bootroot-e2e-ci-reinit-${RUN_ID}" \
SECRETS_DIR="$ROOT_DIR/secrets" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
"$ROOT_DIR/scripts/impl/run-reinit-recovery.sh"

echo "[ci-local-e2e] run step-ca certificate SANs (issue #733)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-stepca-san-${RUN_ID}" \
COMPOSE_PROJECT_NAME="bootroot-e2e-ci-stepca-san-${RUN_ID}" \
SECRETS_DIR="$ROOT_DIR/secrets" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
"$ROOT_DIR/scripts/impl/run-stepca-san.sh"

echo "[ci-local-e2e] run OpenBao TLS no-delta (issue #737)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-openbao-tls-no-delta-${RUN_ID}" \
COMPOSE_PROJECT_NAME="bootroot-e2e-ci-openbao-tls-no-delta-${RUN_ID}" \
SECRETS_DIR="$ROOT_DIR/secrets" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
"$ROOT_DIR/scripts/impl/run-openbao-tls-no-delta.sh"

echo "[ci-local-e2e] run OpenBao TLS re-own (issue #739)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-openbao-tls-reown-${RUN_ID}" \
COMPOSE_PROJECT_NAME="bootroot-e2e-ci-openbao-tls-reown-${RUN_ID}" \
SECRETS_DIR="$ROOT_DIR/secrets" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
"$ROOT_DIR/scripts/impl/run-openbao-tls-reown.sh"

# No COMPOSE_PROJECT_NAME here, unlike the scenarios above: this one has
# to resolve each instance's project from that instance's own `.env`, and
# a caller-supplied project name would collapse both instances into one.
# The script derives its own run-scoped instance names and picks free
# host ports itself, so it needs no port or secrets wiring either.
echo "[ci-local-e2e] run two-instance isolation (issue #747)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-two-instance-${RUN_ID}" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
"$ROOT_DIR/scripts/impl/run-two-instance-isolation.sh"

# The registrar verbs' write-dependent behaviour lives in ignored library
# tests; this scenario is their only gate. It stands its own OpenBao up on
# a free loopback port and needs no compose project, no secrets wiring and
# no bootroot binaries.
echo "[ci-local-e2e] run registrar verbs (issue #758)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-registrar-verbs-${RUN_ID}" \
"$ROOT_DIR/scripts/impl/run-registrar-verbs-e2e.sh"

# The bootroot-internal credential's auth/cert contract — the SAN
# allowlist, the absent `default` policy and the exact-allowlist ACL —
# can only be asserted against a real backend, and only over TLS, since
# `auth/cert` authenticates a client certificate.
echo "[ci-local-e2e] run registrar internal credential (issue #766)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-registrar-internal-${RUN_ID}" \
"$ROOT_DIR/scripts/impl/run-registrar-internal-e2e.sh"

# The provisioning half: a whole deployment on freshly allocated ports,
# with the endpoint predicate seeded before `init`. The moved ports are
# what make a derived step-ca/responder endpoint distinguishable from a
# hard-coded one, and the run-scoped instance name is what makes this
# safe beside a default install.
echo "[ci-local-e2e] run registrar internal credential init (issue #766)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-registrar-internal-init-${RUN_ID}" \
"$ROOT_DIR/scripts/impl/run-registrar-internal-init-e2e.sh"

echo "[ci-local-e2e] run registrar redteam (issue #782)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-registrar-redteam-${RUN_ID}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$ARTIFACT_DIR" \
BOOTROOT_PROJECT_DIR="$ROOT_DIR" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
"$ROOT_DIR/scripts/impl/run-registrar-redteam.sh"

echo "[ci-local-e2e] done"
echo "[ci-local-e2e] artifacts:"
echo "  - $ROOT_DIR/tmp/e2e/ci-local-no-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-local-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-remote-no-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-remote-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-rotation-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-reinit-recovery-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-stepca-san-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-openbao-tls-no-delta-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-openbao-tls-reown-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-two-instance-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-registrar-verbs-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-registrar-internal-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-registrar-internal-init-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-registrar-redteam-${RUN_ID}"
