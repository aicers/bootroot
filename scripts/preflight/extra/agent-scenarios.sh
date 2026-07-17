#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

SCENARIO="${1:-all}"
TIMEOUT_SECS="${TIMEOUT_SECS:-180}"
TMP_DIR="${TMP_DIR:-$ROOT_DIR/tmp/scenarios}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.test.yml)
AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
AGENT_BUILT=0

# bootroot-agent ships as a host daemon, not a container, so these scenarios
# drive the natively built binary. The stack is still compose, so the agent
# reaches step-ca and the responder over the ports they publish to the host
# (normally localhost:9000 and localhost:8080).
CA_CONTAINER_PORT=9000
# The responder listens on two ports: 8080 is the admin API the agent posts
# challenge tokens to, and 80 is the challenge port step-ca fetches during
# validation. Only the admin port is published to the host, because only the
# agent talks to it from there; step-ca reaches port 80 over the compose
# network. This is the admin port -- see wait_for_alias_from_ca for the other.
RESPONDER_ADMIN_CONTAINER_PORT=8080
# Resolved from the running stack by compose_up.
CA_ENDPOINT=""
RESPONDER_ENDPOINT=""

# The compose agent service ran with RUST_LOG=info. Nothing sets it for a host
# process, and the agent's default filter emits ERROR only, so without this the
# logs the failure paths below print would be empty of context.
export RUST_LOG="${RUST_LOG:-info}"

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

load_env_file() {
  if [ -f "$ROOT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$ROOT_DIR/.env"
    set +a
  fi
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return
  fi
  fail "docker compose is not available"
}

current_responder_hmac() {
  if [ -f "$ROOT_DIR/responder.toml.compose" ]; then
    awk -F'"' '/^hmac_secret = / {print $2; exit}' "$ROOT_DIR/responder.toml.compose"
    return
  fi
  if [ -f "$ROOT_DIR/secrets/responder/responder.toml" ]; then
    awk -F'"' '/^hmac_secret = / {print $2; exit}' \
      "$ROOT_DIR/secrets/responder/responder.toml"
    return
  fi
  printf '%s\n' "dev-hmac"
}

ensure_agent_binary() {
  if [ "$AGENT_BUILT" -eq 1 ]; then
    return
  fi
  # Build rather than reuse whatever sits in target/: a binary left by an
  # earlier checkout would let these scenarios pass against code no longer in
  # the tree, which is the one thing a preflight must not do. cargo is a no-op
  # when it is already current. An operator who points BOOTROOT_AGENT_BIN at
  # their own build owns keeping it fresh.
  if [ -z "${BOOTROOT_AGENT_BIN:-}" ]; then
    (cd "$ROOT_DIR" && cargo build --bin bootroot-agent)
  fi
  [ -x "$AGENT_BIN" ] || fail "bootroot-agent binary not executable: $AGENT_BIN"
  AGENT_BUILT=1
}

# Prints the host address a compose service publishes a container port on,
# e.g. "localhost:9000". Asking the running stack keeps this correct when the
# published port is remapped, instead of duplicating docker-compose.yml here.
published_endpoint() {
  local service="$1"
  local container_port="$2"
  local compose_cmd
  local addr
  compose_cmd="$(detect_compose)"

  # Take the first mapping: a wildcard bind can be listed once per address
  # family, and either entry is reachable over loopback.
  addr="$($compose_cmd "${COMPOSE_FILES[@]}" port "$service" "$container_port" 2>/dev/null | head -n 1)"
  addr="${addr%$'\r'}"
  if [ -z "$addr" ]; then
    fail "$service does not publish container port $container_port; is the stack up?"
  fi
  printf '%s\n' "${addr/#0.0.0.0:/localhost:}"
}

# Renders a runtime agent config for the native binary.
#
# The scenario configs are written against the compose stack's internal view:
# step-ca and the responder are named by their Docker network names, and cert
# paths live under the container's /app. A host process resolves none of that,
# so rewrite each container-only value to the host equivalent — the published
# endpoints and the repo-root certs directory — and stamp in the responder HMAC
# the stack is actually running with. Every scenario runs its config through
# this, which is what lets the agent run as the host process it ships as.
materialize_agent_config() {
  local src="$1"
  local dest="$2"
  local responder_hmac
  local ca_endpoint="$CA_ENDPOINT"
  local responder_endpoint="$RESPONDER_ENDPOINT"
  responder_hmac="$(current_responder_hmac)"

  # Endpoints are resolved once while the stack is up. Re-resolving here would
  # break the scenarios that deliberately stop a service before running the
  # agent: the lookup would fail and mask the failure they mean to assert.
  if [ -z "$ca_endpoint" ] || [ -z "$responder_endpoint" ]; then
    fail "host endpoints are unresolved; compose_up must run before the agent"
  fi

  mkdir -p "$(dirname "$dest")"
  # Rules are ordered: the published port is rewritten first, then any
  # remaining CA reference keeps the port the config asked for. That leaves
  # the unreachable-directory scenario's deliberately dead port intact while
  # still moving it onto the host.
  sed -e "s|://bootroot-ca:$CA_CONTAINER_PORT/|://$ca_endpoint/|g" \
    -e "s|://localhost:$CA_CONTAINER_PORT/|://$ca_endpoint/|g" \
    -e "s|://bootroot-ca:|://${ca_endpoint%%:*}:|g" \
    -e "s|http://bootroot-http01:$RESPONDER_ADMIN_CONTAINER_PORT|http://$responder_endpoint|g" \
    -e "s|http://localhost:$RESPONDER_ADMIN_CONTAINER_PORT|http://$responder_endpoint|g" \
    -e "s|\"/app/certs/|\"$ROOT_DIR/certs/|g" \
    -e "s|^http_responder_hmac = \".*\"$|http_responder_hmac = \"$responder_hmac\"|" \
    "$src" > "$dest"
}

run_agent_oneshot() {
  local cfg="$1"
  local runtime="$TMP_DIR/agent.runtime.toml"

  ensure_agent_binary
  materialize_agent_config "$cfg" "$runtime"

  # The compose stack uses a local self-signed CA, so verification is off for
  # these runs exactly as the old container override had it.
  (cd "$ROOT_DIR" && "$AGENT_BIN" --oneshot --insecure --config="$runtime")
}

run_agent_expect_fail() {
  local cfg="$1"
  local expected="$2"
  local output

  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "$expected"; then
    printf "%s\n" "$output"
    fail "Expected failure message not found: $expected"
  fi
}

write_agent_config() {
  local cfg="$1"
  local instance_id="$2"
  local service_name="$3"
  local hostname="$4"
  local cert_path="$5"
  local key_path="$6"
  local domain="${7:-trusted.domain}"

  cat <<TOML > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "$domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "$service_name"
instance_id = "$instance_id"
hostname = "$hostname"

[profiles.paths]
cert = "$cert_path"
key = "$key_path"
TOML
}

# Confirms step-ca can reach the responder's HTTP-01 port under the given
# challenge hostname, which is the name step-ca will fetch during validation.
wait_for_alias_from_ca() {
  local host="$1"

  for _ in $(seq 1 15); do
    if docker exec bootroot-ca bash -lc \
      "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

ensure_network() {
  local network="$1"
  if ! docker network inspect "$network" >/dev/null 2>&1; then
    docker network create "$network" >/dev/null
  fi
}

wait_for_file() {
  local path="$1"
  local timeout="$2"
  local start
  start="$(date +%s)"

  while true; do
    if [ -f "$path" ]; then
      return 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
      return 1
    fi
    sleep 2
  done
}

check_prereqs() {
  require_cmd docker
  require_cmd grep
  # Only the build path needs cargo; an operator supplying their own binary
  # through BOOTROOT_AGENT_BIN does not.
  [ -n "${BOOTROOT_AGENT_BIN:-}" ] || require_cmd cargo

  local compose_cmd
  compose_cmd="$(detect_compose)"
  log "Using compose: $compose_cmd"

  [ -f "$ROOT_DIR/docker-compose.yml" ] || fail "Missing docker-compose.yml"
  [ -f "$ROOT_DIR/docker-compose.test.yml" ] || fail "Missing docker-compose.test.yml"
  [ -f "$ROOT_DIR/agent.toml.compose" ] || fail "Missing agent.toml.compose"
  [ -f "$ROOT_DIR/responder.toml.compose" ] || fail "Missing responder.toml.compose"
  [ -f "$ROOT_DIR/secrets/config/ca.json" ] || fail "Missing secrets/config/ca.json"
  [ -f "$ROOT_DIR/secrets/password.txt" ] || fail "Missing secrets/password.txt"
  [ -f "$ROOT_DIR/secrets/certs/root_ca.crt" ] || fail "Missing secrets/certs/root_ca.crt"

  # Build here, in the parent shell, before any scenario runs. The failure
  # scenarios invoke the agent inside `output="$(... 2>&1)"`, and a build
  # started there would both land in the buffer their assertions grep and
  # lose the AGENT_BUILT memo to the subshell, rebuilding on every one.
  ensure_agent_binary
}

compose_up() {
  local compose_cmd
  compose_cmd="$(detect_compose)"
  log "Starting compose stack"
  $compose_cmd "${COMPOSE_FILES[@]}" up --build -d

  # Read the published endpoints now, while every service is up. Scenarios
  # stop individual services afterwards, and the ports do not move.
  CA_ENDPOINT="$(published_endpoint step-ca "$CA_CONTAINER_PORT")"
  RESPONDER_ENDPOINT="$(published_endpoint bootroot-http01 "$RESPONDER_ADMIN_CONTAINER_PORT")"
}

scenario_oneshot() {
  log "Scenario: happy-compose-oneshot"
  load_env_file
  compose_up

  # Drop artifacts from an earlier run: the assertions below check for
  # existence, and test-core.sh issues to these same paths earlier in
  # run-all.sh, so a leftover file would satisfy them without this run
  # issuing anything.
  rm -f "$ROOT_DIR/certs/bootroot-agent.crt" "$ROOT_DIR/certs/bootroot-agent.key"

  run_agent_oneshot "$ROOT_DIR/agent.toml.compose"

  [ -f "$ROOT_DIR/certs/bootroot-agent.crt" ] || fail "Missing certs/bootroot-agent.crt"
  [ -f "$ROOT_DIR/certs/bootroot-agent.key" ] || fail "Missing certs/bootroot-agent.key"
  log "oneshot issuance ok"
}

scenario_daemon_renewal() {
  log "Scenario: happy-daemon-renewal"
  compose_up
  mkdir -p "$TMP_DIR"

  local cfg="$TMP_DIR/agent.toml.renewal-example"
  cat <<'TOML' > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "bootroot-agent"
instance_id = "001"
hostname = "bootroot-agent"

[profiles.paths]
cert = "/app/certs/renewal-example.crt"
key = "/app/certs/renewal-example.key"

[profiles.daemon]
check_interval = "30s"
renew_before = "2m"
check_jitter = "0s"

[profiles.hooks.post_renew]
success = [
  { command = "sh", args = ["-c", "date > certs/renewed.txt"] }
]
TOML

  local runtime="$TMP_DIR/agent.runtime.renewal.toml"
  ensure_agent_binary
  materialize_agent_config "$cfg" "$runtime"

  # Drop artifacts from an earlier run: both waits below check for existence,
  # so a leftover file would satisfy them without this run issuing anything.
  rm -f "$ROOT_DIR/certs/renewal-example.crt" "$ROOT_DIR/certs/renewal-example.key" \
    "$ROOT_DIR/certs/renewed.txt"

  # `exec` so the subshell becomes the agent and $! is the agent's own pid.
  # Without it bash forks a child and the kill below would only reap the
  # subshell, leaving a daemon renewing into certs/ for the later scenarios.
  local agent_pid
  (cd "$ROOT_DIR" && exec "$AGENT_BIN" --insecure --config="$runtime" \
    >"$TMP_DIR/agent.renewal.log" 2>&1) &
  agent_pid=$!

  local rc=0
  if ! wait_for_file "$ROOT_DIR/certs/renewal-example.crt" "$TIMEOUT_SECS"; then
    rc=1
  elif ! wait_for_file "$ROOT_DIR/certs/renewed.txt" "$TIMEOUT_SECS"; then
    rc=2
  fi

  kill "$agent_pid" 2>/dev/null || true
  wait "$agent_pid" 2>/dev/null || true

  case "$rc" in
    1)
      cat "$TMP_DIR/agent.renewal.log" || true
      fail "Timeout waiting for renewal-example.crt"
      ;;
    2)
      cat "$TMP_DIR/agent.renewal.log" || true
      fail "Timeout waiting for renewed.txt"
      ;;
    *) ;;
  esac
  log "daemon renewal ok"
}

scenario_multi_profile() {
  log "Scenario: happy-multi-profile"
  compose_up
  mkdir -p "$TMP_DIR"

  local compose_override="$TMP_DIR/docker-compose.scenarios.yml"
  cat <<'YAML' > "$compose_override"
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - 201.multi.node-201.trusted.domain
          - 202.multi.node-202.trusted.domain
          - 203.multi.node-203.trusted.domain
YAML

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" -f "$compose_override" up -d bootroot-http01

  local cfg="$TMP_DIR/agent.toml.multi-example"
  cat <<'TOML' > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "multi"
instance_id = "201"
hostname = "node-201"

[profiles.paths]
cert = "certs/multi-201.crt"
key = "certs/multi-201.key"

[[profiles]]
service_name = "multi"
instance_id = "202"
hostname = "node-202"

[profiles.paths]
cert = "certs/multi-202.crt"
key = "certs/multi-202.key"

[[profiles]]
service_name = "multi"
instance_id = "203"
hostname = "node-203"

[profiles.paths]
cert = "certs/multi-203.crt"
key = "certs/multi-203.key"
TOML

  run_agent_oneshot "$cfg"

  [ -f "$ROOT_DIR/certs/multi-201.crt" ] || fail "Missing certs/multi-201.crt"
  [ -f "$ROOT_DIR/certs/multi-202.crt" ] || fail "Missing certs/multi-202.crt"
  [ -f "$ROOT_DIR/certs/multi-203.crt" ] || fail "Missing certs/multi-203.crt"
  log "multi-profile issuance ok"
}

scenario_topology_a() {
  log "Scenario: topology-a-mixed-agents"
  compose_up
  mkdir -p "$TMP_DIR"

  local compose_override="$TMP_DIR/docker-compose.topology-a.yml"
  cat <<'YAML' > "$compose_override"
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - 101.edge-proxy.edge-node-01.trusted.domain
          - 102.edge-proxy.edge-node-02.trusted.domain
          - 103.edge-proxy.edge-node-03.trusted.domain
YAML

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" -f "$compose_override" up -d bootroot-http01

  local cfg_local="$TMP_DIR/agent.toml.topology-a.local"
  local cfg_remote1="$TMP_DIR/agent.toml.topology-a.remote1"
  local cfg_remote2="$TMP_DIR/agent.toml.topology-a.remote2"

  write_agent_config "$cfg_local" "101" "edge-proxy" "edge-node-01" \
    "certs/topo-a-101.crt" "certs/topo-a-101.key"
  write_agent_config "$cfg_remote1" "102" "edge-proxy" "edge-node-02" \
    "certs/topo-a-102.crt" "certs/topo-a-102.key"
  write_agent_config "$cfg_remote2" "103" "edge-proxy" "edge-node-03" \
    "certs/topo-a-103.crt" "certs/topo-a-103.key"

  run_agent_oneshot "$cfg_local"
  run_agent_oneshot "$cfg_remote1"
  run_agent_oneshot "$cfg_remote2"

  [ -f "$ROOT_DIR/certs/topo-a-101.crt" ] || fail "Missing certs/topo-a-101.crt"
  [ -f "$ROOT_DIR/certs/topo-a-102.crt" ] || fail "Missing certs/topo-a-102.crt"
  [ -f "$ROOT_DIR/certs/topo-a-103.crt" ] || fail "Missing certs/topo-a-103.crt"
  log "topology-a issuance ok"
}

scenario_topology_b() {
  log "Scenario: topology-b-split-ca-responder"
  compose_up
  mkdir -p "$TMP_DIR"

  # The split topology puts the responder's challenge names on a dedicated
  # network and joins step-ca to it, so step-ca must resolve the challenge
  # hostnames through the responder's alias on that network rather than
  # through the compose default network. The agent itself is a host process
  # and takes no part in this — it only submits the order.
  local network="bootroot-responder-net"
  ensure_network "$network"

  docker network connect --alias 401.split.edge-node-01.trusted.domain \
    --alias 402.split.edge-node-02.trusted.domain \
    "$network" bootroot-http01 2>/dev/null || true

  docker network connect "$network" bootroot-ca 2>/dev/null || true

  wait_for_alias_from_ca "401.split.edge-node-01.trusted.domain" ||
    fail "step-ca cannot reach the responder via its $network alias"
  wait_for_alias_from_ca "402.split.edge-node-02.trusted.domain" ||
    fail "step-ca cannot reach the responder via its $network alias"

  local cfg1="$TMP_DIR/agent.toml.topology-b.1"
  local cfg2="$TMP_DIR/agent.toml.topology-b.2"
  write_agent_config "$cfg1" "401" "split" "edge-node-01" \
    "certs/topo-b-401.crt" "certs/topo-b-401.key"
  write_agent_config "$cfg2" "402" "split" "edge-node-02" \
    "certs/topo-b-402.crt" "certs/topo-b-402.key"

  run_agent_oneshot "$cfg1"
  run_agent_oneshot "$cfg2"

  [ -f "$ROOT_DIR/certs/topo-b-401.crt" ] || fail "Missing certs/topo-b-401.crt"
  [ -f "$ROOT_DIR/certs/topo-b-402.crt" ] || fail "Missing certs/topo-b-402.crt"
  log "topology-b issuance ok"
}

scenario_fail_responder_down() {
  log "Scenario: fail-responder-down"
  compose_up

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" stop bootroot-http01

  local cfg="$ROOT_DIR/agent.toml.compose"
  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "Failed to register HTTP-01 token"; then
    if ! printf "%s" "$output" | grep -Fq "/admin/http01"; then
      printf "%s\n" "$output"
      fail "Expected responder-down failure not found"
    fi
  fi

  $compose_cmd "${COMPOSE_FILES[@]}" up -d bootroot-http01
  log "responder-down failure ok"
}

scenario_fail_hmac_mismatch() {
  log "Scenario: fail-hmac-mismatch"
  compose_up
  mkdir -p "$TMP_DIR"

  local responder_cfg="$TMP_DIR/responder.toml.bad-hmac"
  cat <<'TOML' > "$responder_cfg"
listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "mismatch-hmac"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
TOML

  local compose_override="$TMP_DIR/docker-compose.bad-hmac.yml"
  cat <<'YAML' > "$compose_override"
services:
  bootroot-http01:
    volumes:
      - ./tmp/scenarios/responder.toml.bad-hmac:/app/responder.toml:ro
YAML

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" -f "$compose_override" up -d bootroot-http01

  local cfg="$ROOT_DIR/agent.toml.compose"
  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "401 Unauthorized"; then
    if ! printf "%s" "$output" | grep -Fq "Invalid signature"; then
      printf "%s\n" "$output"
      fail "Expected HMAC mismatch failure not found"
    fi
  fi

  $compose_cmd "${COMPOSE_FILES[@]}" up -d bootroot-http01
  log "hmac-mismatch failure ok"
}

scenario_fail_dns_unresolvable() {
  log "Scenario: fail-dns-unresolvable"
  compose_up
  mkdir -p "$TMP_DIR"

  local cfg="$TMP_DIR/agent.toml.bad-dns"
  cat <<'TOML' > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "unresolvable.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 3
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "bootroot-agent"
instance_id = "001"
hostname = "bootroot-agent"

[profiles.paths]
cert = "certs/fail-dns.crt"
key = "certs/fail-dns.key"
TOML

  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "validation target"; then
    if ! printf "%s" "$output" | grep -Fq "could not connect"; then
      printf "%s\n" "$output"
      fail "Expected DNS resolution failure not found"
    fi
  fi
  log "dns-unresolvable failure ok"
}

scenario_fail_directory_unreachable() {
  log "Scenario: fail-directory-unreachable"
  compose_up
  mkdir -p "$TMP_DIR"

  local cfg="$TMP_DIR/agent.toml.bad-directory"
  cat <<'TOML' > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9999/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 3
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "bootroot-agent"
instance_id = "001"
hostname = "bootroot-agent"

[profiles.paths]
cert = "certs/fail-directory.crt"
key = "certs/fail-directory.key"
TOML

  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "connection refused"; then
    if ! printf "%s" "$output" | grep -Fq "Connection refused"; then
      if ! printf "%s" "$output" | grep -Fq "error sending request"; then
        printf "%s\n" "$output"
        fail "Expected directory access failure not found"
      fi
    fi
  fi
  log "directory-unreachable failure ok"
}

scenario_fail_domain_empty() {
  log "Scenario: fail-domain-empty"
  compose_up
  mkdir -p "$TMP_DIR"

  local cfg="$TMP_DIR/agent.toml.empty-domain"
  cat <<'TOML' > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = ""

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 3
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "bootroot-agent"
instance_id = "001"
hostname = "bootroot-agent"

[profiles.paths]
cert = "certs/fail-domain-empty.crt"
key = "certs/fail-domain-empty.key"
TOML

  run_agent_expect_fail "$cfg" "domain must not be empty"
  log "domain-empty failure ok"
}

scenario_fail_step_ca_down() {
  log "Scenario: fail-step-ca-down"
  compose_up

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" stop step-ca

  local cfg="$ROOT_DIR/agent.toml.compose"
  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "connection refused"; then
    if ! printf "%s" "$output" | grep -Fq "Connection refused"; then
      if ! printf "%s" "$output" | grep -Fq "error sending request"; then
        printf "%s\n" "$output"
        fail "Expected step-ca down failure not found"
      fi
    fi
  fi

  $compose_cmd "${COMPOSE_FILES[@]}" up -d step-ca
  log "step-ca-down failure ok"
}

scenario_fail_permission_errors() {
  log "Scenario: fail-permission-errors"
  compose_up
  mkdir -p "$TMP_DIR"

  # The compose agent used to get this for free from the read-only ./secrets
  # mount. A host process has no such mount, so deny the write explicitly:
  # the agent creates the profile's parent directories itself, and mkdir
  # inside a 0500 directory is what fails here.
  if [ "$(id -u)" -eq 0 ]; then
    fail "fail-permission-errors must run as a non-root user; root bypasses the mode bits this scenario relies on"
  fi
  local deny_dir="$TMP_DIR/unwritable"
  rm -rf "$deny_dir"
  mkdir -p "$deny_dir"
  chmod 0500 "$deny_dir"

  local cfg="$TMP_DIR/agent.toml.bad-perms"
  cat <<TOML > "$cfg"
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 3
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
service_name = "bootroot-agent"
instance_id = "001"
hostname = "bootroot-agent"

[profiles.paths]
cert = "$deny_dir/denied/fail-perms.crt"
key = "$deny_dir/denied/fail-perms.key"
TOML

  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "Permission denied"; then
    if ! printf "%s" "$output" | grep -Fq "Read-only file system"; then
      if ! printf "%s" "$output" | grep -Fq "Failed to write"; then
      printf "%s\n" "$output"
      fail "Expected permission error not found"
      fi
    fi
  fi
  log "permission failure ok"
}

scenario_fail_db_outage() {
  log "Scenario: fail-db-outage"
  compose_up

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" stop postgres

  local cfg="$ROOT_DIR/agent.toml.compose"
  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "Internal Server Error"; then
    if ! printf "%s" "$output" | grep -Fq "500"; then
      if ! printf "%s" "$output" | grep -Fq "Failed to issue certificate"; then
        printf "%s\n" "$output"
        fail "Expected DB outage failure not found"
      fi
    fi
  fi

  $compose_cmd "${COMPOSE_FILES[@]}" up -d postgres
  log "db-outage failure ok"
}

scenario_fail_eab_required() {
  log "Scenario: fail-eab-required"
  compose_up
  require_cmd python3
  mkdir -p "$TMP_DIR"

  local ca_src="$ROOT_DIR/secrets/config/ca.json"
  local ca_tmp="$TMP_DIR/ca.require-eab.json"
  python3 - <<'PY'
import json
from pathlib import Path

src = Path("secrets/config/ca.json")
data = json.loads(src.read_text())
for p in data.get("authority", {}).get("provisioners", []):
    if p.get("type") == "ACME":
        p["requireEAB"] = True
Path("tmp/scenarios/ca.require-eab.json").write_text(json.dumps(data, indent=2))
PY

  local compose_override="$TMP_DIR/docker-compose.require-eab.yml"
  cat <<'YAML' > "$compose_override"
services:
  step-ca:
    volumes:
      - ./tmp/scenarios/ca.require-eab.json:/home/step/config/ca.json:ro
YAML

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" -f "$compose_override" up -d step-ca

  local cfg="$ROOT_DIR/agent.toml.compose"
  local output
  output="$(run_agent_oneshot "$cfg" 2>&1 || true)"
  if ! printf "%s" "$output" | grep -Fq "externalAccount"; then
    if ! printf "%s" "$output" | grep -Fq "EAB"; then
      printf "%s\n" "$output"
      fail "Expected EAB-required failure not found"
    fi
  fi

  $compose_cmd "${COMPOSE_FILES[@]}" up -d step-ca
  log "eab-required failure ok"
}

check_prereqs

case "$SCENARIO" in
  all)
    scenario_oneshot
    scenario_daemon_renewal
    scenario_multi_profile
    scenario_topology_a
    scenario_topology_b
    scenario_fail_responder_down
    scenario_fail_hmac_mismatch
    scenario_fail_dns_unresolvable
    scenario_fail_directory_unreachable
    scenario_fail_domain_empty
    scenario_fail_step_ca_down
    scenario_fail_permission_errors
    scenario_fail_db_outage
    scenario_fail_eab_required
    ;;
  happy)
    scenario_oneshot
    scenario_daemon_renewal
    scenario_multi_profile
    scenario_topology_a
    scenario_topology_b
    ;;
  failures)
    scenario_fail_responder_down
    scenario_fail_hmac_mismatch
    scenario_fail_dns_unresolvable
    scenario_fail_directory_unreachable
    scenario_fail_domain_empty
    scenario_fail_step_ca_down
    scenario_fail_permission_errors
    scenario_fail_db_outage
    scenario_fail_eab_required
    ;;
  oneshot)
    scenario_oneshot
    ;;
  daemon)
    scenario_daemon_renewal
    ;;
  multi)
    scenario_multi_profile
    ;;
  topology-a)
    scenario_topology_a
    ;;
  topology-b)
    scenario_topology_b
    ;;
  *)
    fail "Unknown scenario: $SCENARIO (use: all|happy|failures|oneshot|daemon|multi|topology-a|topology-b)"
    ;;
esac

log "Done. Temp files: $TMP_DIR"
