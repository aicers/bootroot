#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

SCENARIO="${1:-all}"
TIMEOUT_SECS="${TIMEOUT_SECS:-180}"
TMP_DIR="${TMP_DIR:-$ROOT_DIR/tmp/scenarios}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.test.yml)

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

normalize_stepca_config() {
  if [ -f "$ROOT_DIR/secrets/config/ca.json" ] && [ -x "$ROOT_DIR/scripts/impl/update-ca-db-dsn.sh" ]; then
    log "Updating step-ca DB DSN for compose network"
    "$ROOT_DIR/scripts/impl/update-ca-db-dsn.sh"
  fi

  if [ -f "$ROOT_DIR/secrets/provisioner_password.txt" ]; then
    local pw_file="$ROOT_DIR/secrets/password.txt"
    local prov_file="$ROOT_DIR/secrets/provisioner_password.txt"
    local key_file="$ROOT_DIR/secrets/secrets/intermediate_ca_key"
    if [ -f "$pw_file" ] && [ -f "$prov_file" ] && [ -f "$key_file" ]; then
      if ! cmp -s "$pw_file" "$prov_file"; then
        log "Aligning password.txt with provisioner_password.txt for local scenario"
        cp "$prov_file" "$pw_file"
        chmod 600 "$pw_file" || true
      fi
    fi
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

resolve_agent_image() {
  if docker image inspect bootroot-bootroot-agent:latest >/dev/null 2>&1; then
    echo "bootroot-bootroot-agent:latest"
    return
  fi
  if docker image inspect bootroot-bootroot-agent >/dev/null 2>&1; then
    echo "bootroot-bootroot-agent"
    return
  fi
  fail "bootroot-agent image not found; run compose up --build first"
}

run_agent_oneshot() {
  local cfg="$1"
  local compose_cmd
  compose_cmd="$(detect_compose)"

  $compose_cmd "${COMPOSE_FILES[@]}" run --rm --no-deps \
    --entrypoint /bin/sh \
    -v "$cfg:/app/agent.toml:ro" \
    bootroot-agent -lc \
    "cp /app/agent.toml /app/certs/agent.runtime.toml && \
     exec /app/bootroot-agent --oneshot --config=/app/certs/agent.runtime.toml"
}

run_agent_oneshot_network() {
  local cfg="$1"
  local network="$2"
  local image
  image="$(resolve_agent_image)"

  docker run --rm \
    --entrypoint /bin/sh \
    --network "$network" \
    -v "$ROOT_DIR/certs:/app/certs" \
    -v "$ROOT_DIR/secrets/certs/root_ca.crt:/app/root_ca.crt" \
    -v "$ROOT_DIR/secrets:/app/secrets:ro" \
    -v "$cfg:/app/agent.toml:ro" \
    "$image" -lc \
    "cp /app/agent.toml /app/certs/agent.runtime.toml && \
     exec /app/bootroot-agent --oneshot --config=/app/certs/agent.runtime.toml"
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

ensure_network() {
  local network="$1"
  if ! docker network inspect "$network" >/dev/null 2>&1; then
    docker network create "$network" >/dev/null
  fi
}

wait_for_log() {
  local container="$1"
  local needle="$2"
  local timeout="$3"
  local start
  start="$(date +%s)"

  while true; do
    if docker logs "$container" 2>/dev/null | grep -Fq "$needle"; then
      return 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
      return 1
    fi
    sleep 2
  done
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
}

compose_up() {
  local compose_cmd
  compose_cmd="$(detect_compose)"
  log "Starting compose stack"
  $compose_cmd "${COMPOSE_FILES[@]}" up --build -d
}

scenario_oneshot() {
  log "Scenario: happy-compose-oneshot"
  load_env_file
  normalize_stepca_config
  compose_up

  if ! wait_for_file "$ROOT_DIR/certs/bootroot-agent.crt" "$TIMEOUT_SECS"; then
    fail "Timeout waiting for certs/bootroot-agent.crt"
  fi
  if ! wait_for_file "$ROOT_DIR/certs/bootroot-agent.key" "$TIMEOUT_SECS"; then
    fail "Timeout waiting for certs/bootroot-agent.key"
  fi

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

  local compose_cmd
  compose_cmd="$(detect_compose)"
  $compose_cmd "${COMPOSE_FILES[@]}" run -d --name bootroot-agent-renewal --no-deps \
    --entrypoint /bin/sh \
    -v "$cfg:/app/agent.toml:ro" \
    bootroot-agent -lc \
    "cp /app/agent.toml /app/certs/agent.runtime.toml && \
     exec /app/bootroot-agent --config=/app/certs/agent.runtime.toml"

  if ! wait_for_file "$ROOT_DIR/certs/renewal-example.crt" "$TIMEOUT_SECS"; then
    docker rm -f bootroot-agent-renewal >/dev/null 2>&1 || true
    fail "Timeout waiting for renewal-example.crt"
  fi
  if ! wait_for_file "$ROOT_DIR/certs/renewed.txt" "$TIMEOUT_SECS"; then
    docker rm -f bootroot-agent-renewal >/dev/null 2>&1 || true
    fail "Timeout waiting for renewed.txt"
  fi

  docker rm -f bootroot-agent-renewal >/dev/null 2>&1 || true
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

  $compose_cmd "${COMPOSE_FILES[@]}" run --rm --no-deps \
    --entrypoint /bin/sh \
    -v "$cfg:/app/agent.toml:ro" \
    bootroot-agent -lc \
    "cp /app/agent.toml /app/certs/agent.runtime.toml && \
     exec /app/bootroot-agent --oneshot --config=/app/certs/agent.runtime.toml"

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

  local network="bootroot-responder-net"
  ensure_network "$network"

  docker network connect --alias 401.split.edge-node-01.trusted.domain \
    --alias 402.split.edge-node-02.trusted.domain \
    "$network" bootroot-http01 2>/dev/null || true

  docker network connect --alias bootroot-ca "$network" bootroot-ca 2>/dev/null || true

  local cfg1="$TMP_DIR/agent.toml.topology-b.1"
  local cfg2="$TMP_DIR/agent.toml.topology-b.2"
  write_agent_config "$cfg1" "401" "split" "edge-node-01" \
    "certs/topo-b-401.crt" "certs/topo-b-401.key"
  write_agent_config "$cfg2" "402" "split" "edge-node-02" \
    "certs/topo-b-402.crt" "certs/topo-b-402.key"

  run_agent_oneshot_network "$cfg1" "$network"
  run_agent_oneshot_network "$cfg2" "$network"

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

  local cfg="$TMP_DIR/agent.toml.bad-perms"
  cat <<'TOML' > "$cfg"
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
cert = "secrets/fail-perms.crt"
key = "secrets/fail-perms.key"
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
