# shellcheck shell=bash
# Common support for Docker-backed registrar acceptance scenarios.
#
# The runner is deliberately explicit about its launch inputs. A scenario
# must receive the checkout and the binary it is testing rather than infer
# either from its current directory; wrappers, CI and preflight therefore
# exercise the same contract.

registrar_docker_require_launcher_contract() {
  [ "$#" -eq 0 ] || fail "a registrar scenario launcher takes no positional arguments"
  for registrar_docker_variable in BOOTROOT_PROJECT_DIR BOOTROOT_BIN ARTIFACT_DIR; do
    registrar_docker_value="${!registrar_docker_variable:-}"
    case "$registrar_docker_value" in
      /*) ;;
      *) fail "${registrar_docker_variable} must be an absolute path" ;;
    esac
    [ -e "$registrar_docker_value" ] || fail "${registrar_docker_variable} does not exist: ${registrar_docker_value}"
  done
  [ -d "$BOOTROOT_PROJECT_DIR" ] || fail "BOOTROOT_PROJECT_DIR is not a directory: $BOOTROOT_PROJECT_DIR"
  [ -x "$BOOTROOT_BIN" ] || fail "BOOTROOT_BIN is not executable: $BOOTROOT_BIN"
  [ -d "$ARTIFACT_DIR" ] || fail "ARTIFACT_DIR is not a directory: $ARTIFACT_DIR"
  [ -w "$ARTIFACT_DIR" ] || fail "ARTIFACT_DIR is not writable: $ARTIFACT_DIR"
}

registrar_docker_run_token() {
  local token
  token="${RUN_TOKEN:-${GITHUB_RUN_ID:-local-$(date +%s)-$$}}"
  token="$(printf '%s' "$token" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
  [ -n "$token" ] || fail "RUN_TOKEN reduced to the empty string; use at least one alphanumeric character"
  printf '%s\n' "$token"
}

# Reads a single-line Rust string constant so a Docker scenario can use the
# production spelling without maintaining a second path list. The caller owns
# the constant name; this helper only accepts the declaration form used by the
# repository's path constants.
registrar_docker_rust_string_constant() {
  local source_file="$1" constant_name="$2" value
  value="$(awk -F '"' -v constant_name="$constant_name" '
    $0 ~ "const[[:space:]]+" constant_name "[[:space:]]*:" { print $2 }
  ' "$source_file")"
  [ -n "$value" ] || fail "could not read Rust string constant ${constant_name} from ${source_file}"
  [ "$(printf '%s\n' "$value" | wc -l | tr -d ' ')" = 1 ] ||
    fail "Rust string constant ${constant_name} is ambiguous in ${source_file}"
  printf '%s\n' "$value"
}

# Stages the bounded registrar-leak model. The manifest is intentionally
# evaluated before the recursive credential scan: a missing input is a test
# setup error, never an excuse to scan a wider host or container filesystem.
registrar_docker_stage_leak_bundle() {
  local source_dir="$1" bundle_dir="$2" manifest="$3" entry expected actual
  mkdir -p "$bundle_dir" || fail "could not create registrar leak bundle"
  while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in ''|'#'*) continue ;; esac
    case "$entry" in /*|*'..'*) fail "invalid registrar leak manifest path: $entry" ;; esac
    [ -f "$source_dir/$entry" ] || fail "registrar leak manifest file is absent: $entry"
    mkdir -p "$bundle_dir/$(dirname "$entry")" || fail "could not create bundle parent for $entry"
    cp "$source_dir/$entry" "$bundle_dir/$entry" || fail "could not stage registrar bundle file: $entry"
  done <"$manifest"
  chmod -R a-w "$bundle_dir" || fail "could not make registrar leak bundle read-only"
  expected="$(grep -Ev '^(#|$)' "$manifest" | LC_ALL=C sort)"
  actual="$(cd "$bundle_dir" && find . -type f -print | sed 's|^./||' | LC_ALL=C sort)"
  [ "$actual" = "$expected" ] || fail "staged registrar regular-file set differs from its manifest"
}

registrar_docker_assert_no_backend_credentials() {
  local bundle_dir="$1" label_pattern bare_value_pattern
  # These are credential values, not filenames. An AppRole identifier is a
  # UUID and OpenBao issues `hvs.`, `hvb.`, and legacy `s.` tokens. Match
  # those values directly as well as conventional labels, because copied
  # material need not retain the field name it had when it was created.
  # Restricting the recursive scan to the read-only bundle is the threat-model
  # boundary; daemon material is never an attacker input in this scenario.
  # Only labels are case-insensitive. Token prefixes remain the explicitly
  # supported bare-value forms rather than accepting a new casing variant.
  label_pattern="(X-(Vault|OpenBao)-Token|OPENBAO_TOKEN|VAULT_TOKEN|[\"']?(role_id|secret_id)[\"']?[[:space:]]*[:=])"
  bare_value_pattern="(hvs\.[[:alnum:]_-]{8,}|hvb\.[[:alnum:]_-]{8,}|s\.[[:alnum:]_-]{8,}|[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12})"
  if LC_ALL=C grep -RInEi "$label_pattern" "$bundle_dir" ||
    LC_ALL=C grep -RInE "$bare_value_pattern" "$bundle_dir"; then
    fail "the registrar leak bundle contains an OpenBao or AppRole credential"
    return 1
  fi
}

# Creates the minimal deployment tree consumed by registrar Docker scenarios.
# `docker-compose.deploy.yml` has no build context, but it resolves these two
# files relative to itself. Keeping the copy rule here means the endurance arm
# and this per-PR arm cannot slowly grow different private deployments.
registrar_docker_prepare_deployment_tree() {
  local project_dir="$1" work_dir="$2"
  mkdir -p "$work_dir/openbao" || fail "could not create registrar deployment tree"
  cp "$project_dir/docker-compose.deploy.yml" "$work_dir/" ||
    fail "could not copy the deploy compose file"
  cp "$project_dir/openbao/openbao.hcl" "$work_dir/openbao/" ||
    fail "could not copy the OpenBao configuration"
  cp "$project_dir/responder.toml.compose" "$work_dir/" ||
    fail "could not copy the responder configuration"
}

# ---------------------------------------------------------------------------
# Shared isolated-deployment and daemon-supervisor setup
# ---------------------------------------------------------------------------
#
# Both Docker-backed registrar scenarios — the per-pull-request red-team arm
# and the extended-tier endurance arm — stand the same deployment up before
# they diverge: a run-scoped Compose project on four freshly allocated host
# ports, `bootroot init` under `sudo`, the registrar DNS aliases step-ca
# resolves its challenge through, and a root-owned inherited listener under a
# small Python supervisor. Only what each scenario then asserts, and how long
# it waits, differs. That setup lives here once so the two arms cannot slowly
# grow different deployments; each scenario's assertions and workload stay in
# its own script, and nothing scenario-specific belongs here.
#
# These functions read and write the run's own shell variables rather than
# taking each as an argument. RUN_ROOT, WORK_DIR, INSTANCE and the paths below
# are the run's identity, and every scenario needs them under exactly those
# names afterwards; passing them in and out again would only add a second
# spelling of each. Every function states what it requires and what it leaves
# set.
#
# Requires a caller-defined `fail`, `lib/ports.sh` for `pick_free_port`, the
# launcher contract's BOOTROOT_PROJECT_DIR, BOOTROOT_BIN and ARTIFACT_DIR, the
# derived INSTANCE and RUN_TOKEN, and RUN_LOG — the scenario log every command
# below appends its output to.

# The instance-name budget `infra install` validates `--instance-name`
# against: `MAX_INSTANCE_NAME_LEN` in src/commands/compose_project.rs, the
# DNS-label limit less the longest container-name suffix. The binary rejects a
# longer name outright rather than normalising it, so a name derived past this
# fails the install minutes into a run. `scripts/validate-e2e-run-scope.sh`
# holds this literal to the value the binary derives.
REGISTRAR_DOCKER_MAX_INSTANCE_NAME_LEN=39

# Derives this run's instance name from a scenario prefix and the run token.
#
# The tail is what survives when a token does not fit: a suite token ends in
# the launcher PID, which is the part that differs between concurrent runs of
# the same scenario. A token already inside the budget is kept whole — Bash's
# negative substring offset yields the empty string for a token shorter than
# the offset, so the two cases cannot be one expression. The complete token
# still scopes artifact paths and image tags, neither of which is bounded.
registrar_docker_instance_name() {
  local prefix="$1" token="$2" budget
  budget=$((REGISTRAR_DOCKER_MAX_INSTANCE_NAME_LEN - ${#prefix}))
  [ "$budget" -ge 1 ] ||
    fail "the instance-name prefix '${prefix}' leaves no room for a run token within ${REGISTRAR_DOCKER_MAX_INSTANCE_NAME_LEN} characters"
  [ -n "$token" ] || fail "a registrar scenario instance name needs a non-empty run token"
  [ "${#token}" -le "$budget" ] || token="${token:$((${#token} - budget))}"
  printf '%s%s\n' "$prefix" "$token"
}

# `docker compose` and `bootroot` for this run's deployment. Both resolve the
# compose file copied into the run root and the run-scoped instance, so no
# caller spells either out.
registrar_docker_compose() {
  BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" \
    -f "$WORK_DIR/docker-compose.deploy.yml" "$@"
}

registrar_docker_bootroot() {
  (cd "$WORK_DIR" && "$BOOTROOT_BIN" "$@")
}

registrar_docker_sha256_file() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Creates the run root, every path the two scenarios share, and the
# scenario-local audit tmpfs. `slug` scopes the temporary directory's name.
#
# The audit store is a run-local tmpfs rather than a directory on the host
# filesystem: it bounds what the daemon can write without a quota on the host,
# and it takes the run's audit records with it when the run ends. Its size is
# fixed here rather than per scenario because the red-team arm fills it to its
# low-water and exhausted thresholds, and those thresholds are chosen against
# this figure.
#
# Leaves set: RUN_ROOT, WORK_DIR, AUDIT_DIR, RECORD_DIR, SURFACE_DIR,
# SOCKET_DIR, SOCKET_PATH, CONTROL_FIFO, DAEMON_CONFIG, PROVISIONING,
# INITIAL_CONFIG, SUMMARY, TOKEN_FILE, TOKEN_CURL, and — once the mount
# succeeds — AUDIT_TMPFS_MOUNTED, the flag the caller's own cleanup unmounts
# on. A scenario adds whatever further run-root paths it needs after this
# returns; it does not re-derive these.
#
# shellcheck disable=SC2034 # every name below is the caller's, by contract.
registrar_docker_prepare_run_root() {
  local slug="$1"
  RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bootroot-registrar-${slug}-XXXXXX")"
  WORK_DIR="$RUN_ROOT/bootroot"
  AUDIT_DIR="$RUN_ROOT/audit"
  RECORD_DIR="$AUDIT_DIR/records"
  SURFACE_DIR="$RUN_ROOT/surface"
  SOCKET_DIR="$RUN_ROOT/socket"
  SOCKET_PATH="$SOCKET_DIR/registrar.sock"
  CONTROL_FIFO="$RUN_ROOT/agent-control"
  DAEMON_CONFIG="$RUN_ROOT/registrar-agent.toml"
  PROVISIONING="$RUN_ROOT/provisioning.toml"
  INITIAL_CONFIG="$WORK_DIR/operator-agent.toml"
  SUMMARY="$RUN_ROOT/init-summary.json"
  TOKEN_FILE="$RUN_ROOT/openbao-root-token"
  TOKEN_CURL="$RUN_ROOT/openbao-curl.conf"
  mkdir -p "$AUDIT_DIR" "$SURFACE_DIR" "$SOCKET_DIR" ||
    fail "could not create the scenario run root"
  registrar_docker_prepare_deployment_tree "$BOOTROOT_PROJECT_DIR" "$WORK_DIR"
  chmod 0755 "$RUN_ROOT"
  sudo -n chown 0:0 "$AUDIT_DIR" "$SOCKET_DIR"
  sudo -n chmod 0700 "$AUDIT_DIR"
  sudo -n chmod 0755 "$SOCKET_DIR"
  sudo -n mount -t tmpfs -o size=16m,mode=0700 tmpfs "$AUDIT_DIR" ||
    fail "could not mount the scenario-local audit tmpfs"
  AUDIT_TMPFS_MOUNTED=1
}

# Allocates the four host ports this run's deployment publishes.
#
# Leaves set: PORT_POSTGRES, PORT_OPENBAO, PORT_STEPCA, PORT_HTTP01, and
# OPENBAO_URL — the TLS URL OpenBao answers on once `init` has reowned it.
registrar_docker_allocate_ports() {
  local name
  for name in POSTGRES OPENBAO STEPCA HTTP01; do
    pick_free_port
    printf -v "PORT_${name}" '%s' "$PICKED_PORT"
  done
  OPENBAO_URL="https://localhost:${PORT_OPENBAO}"
}

# Writes the two configuration files `init` is given: the fingerprinted
# provisioning config, and the operator agent config naming this run's audit
# store. The caller owns only the component body — the one part of these that
# the two scenarios genuinely differ on — and hands it over as a file, which
# this consumes.
registrar_docker_write_configs() {
  local body="$1"
  printf 'fingerprint = "%s"\n' "$(registrar_docker_sha256_file "$body")" >"$PROVISIONING"
  cat "$body" >>"$PROVISIONING"
  rm -f "$body"
  cat >"$INITIAL_CONFIG" <<EOF
[registrar]
audit_store_dir = "${AUDIT_DIR}"
audit_store_enforcement = "directory"

[registrar_endpoint]
enabled = true
EOF
}

# `infra install --no-build` deliberately passes `--pull never`. Pull the
# three non-repository images through this copied compose file so its tags
# remain the only source of truth for the deployment under test.
registrar_docker_prepull_third_party_images() {
  POSTGRES_PASSWORD=prepull-only GRAFANA_ADMIN_PASSWORD=prepull-only \
    registrar_docker_compose pull openbao postgres step-ca >>"$RUN_LOG" 2>&1 ||
    fail "could not pre-pull third-party deployment images"
}

# Records the explicit empty agent EAB that `init --no-eab` leaves absent.
#
# The registrar's production reader distinguishes an explicitly cleared EAB
# payload from a missing KV entry, so the isolated deployment needs the former
# written before the daemon starts. The exchange is kept as artifacts because
# anything other than a 200 here surfaces much later, as a daemon that cannot
# read a credential rather than as a setup step that did not happen.
registrar_docker_record_empty_agent_eab() {
  local status
  status="$(sudo -n curl -sS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" -X POST \
    --data '{"data":{"kid":"","hmac":""}}' \
    --dump-header "$ARTIFACT_DIR/empty-eab-headers.txt" \
    --output "$ARTIFACT_DIR/empty-eab-response.json" \
    --write-out '%{http_code}' \
    "$OPENBAO_URL/v1/secret/data/bootroot/agent/eab")" || status="curl-failed"
  printf '%s\n' "$status" >"$ARTIFACT_DIR/empty-eab-status.txt"
  if [ "$status" != "200" ]; then
    cat "$ARTIFACT_DIR/empty-eab-status.txt" "$ARTIFACT_DIR/empty-eab-headers.txt" \
      "$ARTIFACT_DIR/empty-eab-response.json" >>"$RUN_LOG" 2>/dev/null || true
    fail "could not record the explicit empty agent EAB"
  fi
}

# Builds the responder image, installs the deployment on the allocated ports,
# and runs `init` to completion under `sudo`.
#
# `slug` is the scenario's own name and the only value that differs between
# the two runs of this: it scopes the responder image tag, both init secrets,
# and the endpoint host label the state predicate is seeded with.
#
# `init` has already recreated the responder with its rendered HMAC and
# started the OpenBao agents by the time this returns. Replaying `infra up`
# afterwards races that rendered configuration with the base image and leaves
# the registrar's pre-issued HMAC unable to authenticate to the responder.
#
# Leaves set: HTTP01_IMAGE and the exported BOOTROOT_HTTP01_IMAGE,
# HTTP01_IMAGE_BUILT once the build succeeds — the flag the caller's cleanup
# removes the image on — the contents of TOKEN_FILE and TOKEN_CURL, and
# OPENBAO_CA.
#
# shellcheck disable=SC2034 # HTTP01_IMAGE_BUILT is the caller's cleanup flag.
# shellcheck disable=SC2024 # the invoking user owns the run root the raw init
# log is captured into; only the command being run needs to be root.
registrar_docker_build_and_initialize() {
  local slug="$1" init_raw_log="$RUN_ROOT/init.raw.log"
  HTTP01_IMAGE="bootroot-http01-responder:registrar-${slug}-${RUN_TOKEN}"
  export BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE"
  docker build -t "$HTTP01_IMAGE" -f "$BOOTROOT_PROJECT_DIR/docker/http01-responder/Dockerfile" \
    "$BOOTROOT_PROJECT_DIR" >>"$RUN_LOG" 2>&1 || fail "could not build responder image"
  HTTP01_IMAGE_BUILT=1
  registrar_docker_prepull_third_party_images
  registrar_docker_bootroot infra install --compose-file "$WORK_DIR/docker-compose.deploy.yml" \
    --instance-name "$INSTANCE" --postgres-host-port "$PORT_POSTGRES" \
    --openbao-host-port "$PORT_OPENBAO" --stepca-host-port "$PORT_STEPCA" \
    --http01-admin-host-port "$PORT_HTTP01" --no-build >>"$RUN_LOG" 2>&1 ||
    fail "infra install failed"
  for _ in $(seq 1 60); do
    curl -fsS "http://localhost:${PORT_OPENBAO}/v1/sys/seal-status" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS "http://localhost:${PORT_OPENBAO}/v1/sys/seal-status" >/dev/null 2>&1 ||
    fail "OpenBao did not become reachable"
  # A fresh `infra install` deliberately creates no state inventory. Seed
  # the one endpoint predicate `init` must preserve while it writes the
  # complete state record after provisioning.
  jq -n --arg url "http://localhost:${PORT_OPENBAO}" --arg host "$slug" \
    '{openbao_url: $url, kv_mount: "secret", registrar_endpoint: {enabled: true, domain: "trusted.domain", host: $host}}' \
    >"$WORK_DIR/state.json" || fail "could not seed endpoint predicate"
  if ! sudo -n env HOME="$HOME" BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE" bash -c 'cd "$1" && exec "$2" init --compose-file "$3" --secrets-dir "$4" --enable auto-generate,show-secrets,db-provision --stepca-password "$5" --http-hmac "$6" --no-eab --save-unseal-keys --overwrite-password --overwrite-ca-json --overwrite-state --confirm-db-provision --db-user step --db-name stepca --responder-url "$7" --agent-config "$8" --summary-json "$9"' _ "$WORK_DIR" "$BOOTROOT_BIN" "$WORK_DIR/docker-compose.deploy.yml" "$WORK_DIR/secrets" "${slug}-${RUN_TOKEN}" "${slug}-hmac-${RUN_TOKEN}" "http://127.0.0.1:${PORT_HTTP01}" "$INITIAL_CONFIG" "$SUMMARY" </dev/null >"$init_raw_log" 2>&1; then
    sed 's/^\(root token: \).*/\1<redacted>/' "$init_raw_log" >"$ARTIFACT_DIR/init.log" || true
    fail "bootroot init failed"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$init_raw_log" >"$ARTIFACT_DIR/init.log"
  sudo -n jq -r '.root_token // empty' "$SUMMARY" | sudo -n sh -c 'umask 077; cat >"$1"' _ "$TOKEN_FILE"
  sudo -n test -s "$TOKEN_FILE" || fail "init did not write a root token"
  # A header file keeps the init root token out of the process arguments.
  # `curl --header @file` consumes the literal HTTP field line, unlike a
  # curl config file where an extra escape would change the field name.
  sudo -n sh -c 'printf "%s: %s\n" "X-Vault-Token" "$(cat "$1")" >"$2"; chmod 600 "$2"' _ "$TOKEN_FILE" "$TOKEN_CURL"
  OPENBAO_CA="$RUN_ROOT/openbao-ca.pem"
  sudo -n sh -c 'cat "$1" "$2" >"$3"; chmod 644 "$3"' _ "$WORK_DIR/secrets/certs/root_ca.crt" "$WORK_DIR/secrets/certs/intermediate_ca.crt" "$OPENBAO_CA"
  registrar_docker_record_empty_agent_eab
}

# Reads the KV mount `init` recorded and the two production KV paths both
# scenarios name. A scenario needing further path constants reads them with
# `registrar_docker_rust_string_constant` itself.
#
# Leaves set: KV_MOUNT, RESPONDER_HMAC_PATH, AGENT_EAB_PATH.
#
# shellcheck disable=SC2034 # all three are read by the calling scenario.
registrar_docker_load_openbao_paths() {
  local init_constants="$BOOTROOT_PROJECT_DIR/src/commands/init/constants.rs"
  KV_MOUNT="$(jq -er '.kv_mount' "$WORK_DIR/state.json")" || fail "init did not record the KV mount"
  RESPONDER_HMAC_PATH="$(registrar_docker_rust_string_constant "$init_constants" PATH_RESPONDER_HMAC)"
  AGENT_EAB_PATH="$(registrar_docker_rust_string_constant "$init_constants" PATH_AGENT_EAB)"
}

# Gives the responder container both registrar hostnames as network aliases,
# and proves step-ca resolves and reaches each one.
#
# The endpoint's HTTP-01 challenge is answered by the responder under the
# registrar's own name, so a missing alias surfaces as an issuance that never
# completes rather than as a name that does not resolve. The override is
# written into the artifact directory so a failed run keeps it.
registrar_docker_apply_endpoint_dns_alias() {
  local client_alias="$1" endpoint_alias="$2" alias
  local override="$ARTIFACT_DIR/docker-compose.registrar-endpoint-alias.yml"
  local responder_override="$WORK_DIR/secrets/responder/docker-compose.responder.override.yml"
  cat >"$override" <<EOF
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - ${client_alias}
          - ${endpoint_alias}
EOF
  [ -f "$responder_override" ] || fail "init did not render the responder compose override"
  BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" \
    -f "$WORK_DIR/docker-compose.deploy.yml" -f "$override" -f "$responder_override" \
    up -d --no-deps bootroot-http01 >>"$RUN_LOG" 2>&1 ||
    fail "could not apply the registrar endpoint DNS aliases"
  for alias in "$client_alias" "$endpoint_alias"; do
    for _ in $(seq 1 15); do
      if docker exec "${INSTANCE}-ca" bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${alias}/80'" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    docker exec "${INSTANCE}-ca" bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${alias}/80'" >/dev/null 2>&1 ||
      fail "step-ca cannot reach registrar hostname ${alias} through its DNS alias"
  done
}

# Writes the root-owned daemon configuration: the internal agent config `init`
# rendered, followed by this run's registrar and endpoint sections.
#
# `extra_registrar_keys`, when given, is appended inside `[registrar]`. It is
# where a scenario puts a key only it needs — the red-team arm's audit-store
# budget — and it is the only part of this file the two arms differ on.
#
# Leaves set: INTERNAL_DIR, ROOT_CA, and the root-owned RECORD_DIR.
#
# shellcheck disable=SC2034 # ROOT_CA is the anchor each scenario then pins.
registrar_docker_write_daemon_config() {
  local extra_registrar_keys="${1:-}"
  INTERNAL_DIR="$WORK_DIR/secrets/registrar-internal"
  ROOT_CA="$WORK_DIR/secrets/certs/root_ca.crt"
  {
    cat <<EOF

[registrar]
state_file = "${WORK_DIR}/state.json"
provisioning_config_path = "${PROVISIONING}"
audit_store_dir = "${AUDIT_DIR}"
audit_record_dir = "${RECORD_DIR}"
audit_store_enforcement = "directory"
EOF
    [ -z "$extra_registrar_keys" ] || printf '%s\n' "$extra_registrar_keys"
    cat <<EOF

[registrar_endpoint]
enabled = true
server_cert_path = "${SURFACE_DIR}/registrar-endpoint.crt"
server_key_path = "${SURFACE_DIR}/registrar-endpoint.key"
client_cert_path = "${SURFACE_DIR}/registrar-client.crt"
client_key_path = "${SURFACE_DIR}/registrar-client.key"
EOF
  } >"$RUN_ROOT/endpoint.toml"
  sudo -n sh -c 'cat "$1" "$2" >"$3"; chmod 600 "$3"; chown 0:0 "$3"' _ "$INTERNAL_DIR/agent.toml" "$RUN_ROOT/endpoint.toml" "$DAEMON_CONFIG"
  sudo -n mkdir -p "$RECORD_DIR"
  sudo -n chown 0:0 "$RECORD_DIR"
  sudo -n chmod 0700 "$RECORD_DIR"
}

# Writes the supervisor the daemon runs under.
#
# The deployed daemon inherits its listener rather than binding one, so
# something has to own that socket across a restart. This parent binds it,
# makes it root-owned 0700, and hands it over as fd 3 under the `LISTEN_FDS`
# protocol; the control FIFO then drives restart, stop and quit without the
# socket ever being rebound. Both scenarios depend on that inode surviving a
# restart, so there is one supervisor rather than one each.
registrar_docker_write_supervisor() {
  cat >"$RUN_ROOT/supervisor.py" <<'PY'
import os, signal, socket, sys
sock_path, control, pid_file, agent_bin, config = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.bind(sock_path); sock.listen(32); os.chown(sock_path, 0, 0); os.chmod(sock_path, 0o700); os.mkfifo(control, 0o600); child = None
def spawn():
    global child
    child = os.fork()
    if child == 0:
        os.dup2(sock.fileno(), 3); os.set_inheritable(3, True); env = os.environ.copy(); env['LISTEN_PID'] = str(os.getpid()); env['LISTEN_FDS'] = '1'; os.execvpe(agent_bin, [agent_bin, '--config', config], env)
    open(pid_file, 'w', encoding='ascii').write(str(child))
def stop():
    global child
    if child is not None:
        try: os.kill(child, signal.SIGTERM)
        except ProcessLookupError: pass
        os.waitpid(child, 0); child = None
spawn()
while True:
    with open(control, encoding='ascii') as stream:
        for line in stream:
            if line.strip() == 'restart': stop(); spawn()
            elif line.strip() == 'stop': stop()
            elif line.strip() == 'quit': stop(); sys.exit(0)
PY
}

# Sends one word — `restart`, `stop` or `quit` — to the supervisor's FIFO.
registrar_docker_control() {
  printf '%s\n' "$1" | sudo -n tee "$CONTROL_FIFO" >/dev/null
}

# Starts the supervisor as root in the background.
#
# Any arguments are a launch prefix placed before `python3`: the endurance
# arm's `env` and `strace` wrapper, which the red-team arm does not use. The
# supervisor's own output goes to the scenario's agent log, so the daemon's
# startup diagnostics survive a failed run.
#
# Leaves set: SUPERVISOR_PID, the background parent the caller's cleanup stops.
#
# shellcheck disable=SC2024 # the invoking user owns the artifact directory the
# supervisor's output is appended to; only the supervisor itself needs to be
# root.
registrar_docker_start_supervisor() {
  registrar_docker_write_supervisor
  sudo -n "$@" python3 "$RUN_ROOT/supervisor.py" "$SOCKET_PATH" "$CONTROL_FIFO" \
    "$RUN_ROOT/agent.pid" "$BOOTROOT_AGENT_BIN" "$DAEMON_CONFIG" \
    >>"$ARTIFACT_DIR/agent.log" 2>&1 &
  SUPERVISOR_PID=$!
}

# True when every named surface certificate exists and is non-empty.
#
# Read through `sudo`: the daemon writes this material as root, and a
# readability difference must not be mistaken for material that is not there
# yet.
registrar_docker_surface_material_present() {
  local material
  for material in "$@"; do
    sudo -n test -s "$material" || return 1
  done
}

# Waits for the socket, the daemon's pid file, and every named piece of
# surface material. The caller names the material because that is where the
# two scenarios differ: the red-team arm needs the client leaf it hands the
# attacker, and the endurance arm needs both leaves it watches across renewal.
registrar_docker_await_surface_material() {
  for _ in $(seq 1 90); do
    [ -S "$SOCKET_PATH" ] && [ -s "$RUN_ROOT/agent.pid" ] &&
      registrar_docker_surface_material_present "$@" && break
    sleep 1
  done
  registrar_docker_surface_material_present "$@" ||
    fail "daemon did not issue registrar surface material"
}

# Stops the supervisor and the daemon it owns, and reaps both.
#
# `quit` is the ordinary path: the supervisor terminates its child and exits.
# The signal fallback covers a supervisor that has stopped reading its FIFO —
# the daemon is signalled through the pid file it wrote, because it is root's
# child and not this shell's.
registrar_docker_stop_supervisor() {
  [ -n "${SUPERVISOR_PID:-}" ] && kill -0 "$SUPERVISOR_PID" 2>/dev/null || return 0
  registrar_docker_control quit || true
  for _ in $(seq 1 15); do
    kill -0 "$SUPERVISOR_PID" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
    [ -s "$RUN_ROOT/agent.pid" ] && sudo -n kill -TERM "$(cat "$RUN_ROOT/agent.pid")" 2>/dev/null || true
    kill -TERM "$SUPERVISOR_PID" 2>/dev/null || true
  fi
  wait "$SUPERVISOR_PID" 2>/dev/null || true
}
