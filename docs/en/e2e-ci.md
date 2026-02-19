# CI & E2E

This page explains bootroot CI/E2E validation structure, scenario execution
flows, local preflight steps, and failure check criteria.

## CI workflow layout

PR-critical CI (`.github/workflows/ci.yml`) runs:

- `test-core`: unit/integration smoke path
- `test-docker-e2e-matrix`: Docker E2E test set for end-to-end flow + rotation/recovery

Extended E2E (`.github/workflows/e2e-extended.yml`) runs separately:

- `workflow_dispatch` (manual trigger)
- scheduled trigger at `23:30 KST` (UTC cron), gated by same-day `main` commit
  activity (KST)

The extended workflow is for heavier resilience/stress testing and is kept
outside the PR-critical path.

## E2E terms and scenario axes

Term definitions:

- `control node`: machine that runs `bootroot`, hosts step-ca and OpenBao,
  and handles infra initialization plus service state recording
- `remote node`: machine that runs `bootroot-remote` and applies local
  file/config updates for the service

E2E scenarios are defined by combining two independent axes:

1. delivery mode (`bootroot service add --delivery-mode`)
2. host name mapping mode (E2E script run mode)

Delivery mode (`--delivery-mode`):

- `local-file`: a `--delivery-mode` option. Used when the service is added on
  the same machine where step-ca/OpenBao/responder run.
- `remote-bootstrap`: a `--delivery-mode` option. Used when the service is
  added on a different machine; it combines control-node `bootroot` with
  service-node `bootroot-remote sync`.

Host name mapping mode (E2E run mode):

- `fqdn-only-hosts`: an E2E script mode name. It does not modify host-machine
  `/etc/hosts`; it connects to step-ca and responder via `localhost`/IP.
- `hosts-all`: an E2E script mode name. It adds host-machine `/etc/hosts`
  entries for `stepca.internal` and `responder.internal`, then connects by
  those names. In E2E, entries are added during the run and removed in cleanup;
  in production, DNS/hosts must be managed continuously.

Common behavior: both mapping modes add service FQDN -> responder IP mappings
in the step-ca container `/etc/hosts` so SAN targets are reachable.

## Docker E2E test scope

PR-critical Docker test set validates:

- local-delivery E2E scenario (`fqdn-only-hosts`)
- local-delivery E2E scenario (`hosts-all`)
- remote-delivery E2E scenario (`fqdn-only-hosts`)
- remote-delivery E2E scenario (`hosts-all`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)

Primary scripts:

- `scripts/e2e/docker/run-main-lifecycle.sh`
- `scripts/e2e/docker/run-main-remote-lifecycle.sh`
- `scripts/e2e/docker/run-rotation-recovery.sh`

Extended workflow validates:

- baseline scale/contention behavior
- repeated failure/recovery behavior
- periodic execution mode parity (`systemd-timer`, `cron`)

Primary script:

- `scripts/e2e/docker/run-extended-suite.sh`

## Scenario details and execution steps

This section repeats key context from other manual pages on purpose.
Use this page alone as a runbook for CI/E2E understanding and reproduction.

### 1) local-delivery E2E scenario (`fqdn-only-hosts`)

Configuration:

- Single machine baseline used by `scripts/e2e/docker/run-main-lifecycle.sh`
- `openbao`, `postgres`, `step-ca`, `bootroot-http01` run in Docker Compose
- Services are added with `--delivery-mode local-file`
- Service set in this scenario (2 services): `edge-proxy` (`daemon`),
  `web-app` (`docker`)
- Resolution mode is `fqdn-only-hosts` (no `/etc/hosts` mutation)

Purpose:

- Validate the default same-machine onboarding path end-to-end
- Validate `bootroot init` -> `service add` -> `verify` flow
- Validate rotation + reissue behavior in the same-machine path

Execution steps:

1. `infra-up`: bring up Compose services and wait for readiness
2. `init`: run `bootroot init --summary-json` and read `root_token` from JSON
3. `service-add`: add daemon + docker services in `local-file` mode
4. `verify-initial`: issue/verify initial certs and snapshot fingerprints
5. `rotate-responder-hmac`: run rotation and force reissue
6. `verify-after-responder-hmac`: verify certs again and confirm fingerprint changes
7. `cleanup`: capture logs/artifacts and tear down Compose

Actual commands (script excerpt):

```bash
# 1) infra-up
bootroot infra up --compose-file "$COMPOSE_FILE"

# 2) init
BOOTROOT_LANG=en printf "y\ny\nn\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" \
  --secrets-dir "$SECRETS_DIR" \
  --summary-json "$INIT_SUMMARY_JSON" \
  --auto-generate --show-secrets \
  --stepca-url "$STEPCA_EAB_URL" \
  --db-dsn "postgresql://step:step-pass@postgres:5432/step?sslmode=disable" \
  --responder-url "$RESPONDER_URL"

# 3) service-add
bootroot service add --service-name edge-proxy --deploy-type daemon \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"
bootroot service add --service-name web-app --deploy-type docker \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"

# 4) verify-initial / 6) verify-after-responder-hmac
bootroot verify --service-name edge-proxy --agent-config "$AGENT_CONFIG_PATH"
bootroot verify --service-name web-app --agent-config "$AGENT_CONFIG_PATH"

# 5) rotate-responder-hmac
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" --root-token "$OPENBAO_ROOT_TOKEN" \
  --yes responder-hmac
```

### 2) local-delivery E2E scenario (`hosts-all`)

Configuration:

- Same script and same-machine topology as above
- Same service set as `fqdn-only-hosts`: `edge-proxy` (`daemon`), `web-app` (`docker`)
- Resolution mode is `hosts-all`
- Script writes temporary `stepca.internal` / `responder.internal` host entries
  (requires `sudo -n`)

Purpose:

- Validate hostname-based resolution path used by `hosts-all`
- Catch breakage tied to `/etc/hosts`-driven name resolution

Execution steps:

1. Add host entries for `stepca.internal` and `responder.internal`
2. Run the same end-to-end flow phases as `fqdn-only-hosts`
3. Remove temporary host entries during cleanup

Actual commands (script excerpt):

```bash
# run in hosts-all mode
RESOLUTION_MODE=hosts-all ./scripts/e2e/docker/run-main-lifecycle.sh

# internal host-entry add/remove sequence
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 3) remote-delivery E2E scenario (`fqdn-only-hosts`)

Configuration:

- Two workspaces in one run: `control node` (step-ca machine role),
  `remote node` (service machine role)
- Service is added with `--delivery-mode remote-bootstrap`
- Service set in this scenario (1 service): `edge-proxy` (`daemon`)
- Remote sync apply is executed by `bootroot-remote sync`
- Resolution mode is `fqdn-only-hosts`

Purpose:

- Validate remote-bootstrap onboarding and remote sync-apply path
- Validate sync/ack-driven `sync_status` updates for
  `secret_id`, `eab`, `responder_hmac`, `trust_sync`
- Validate remote rotation/recovery sequence across all sync items

Execution steps:

1. `infra-up`, `init` on control node, then parse `root_token` from summary JSON
2. `service-add` in `remote-bootstrap` mode (control node writes desired state)
3. Copy bootstrap materials (`role_id`, `secret_id`) to remote node
4. `sync-initial`: run `bootroot-remote sync` on remote node
5. Assert control-node `state.json` sync status is `applied`
6. `verify-initial`: issue/verify certificate on remote node
7. Rotation + sync + verify cycles: `rotate-secret-id` -> `sync-after-secret-id`
   -> `verify-after-secret-id`,
   `rotate-eab` -> `sync-after-eab` -> `verify-after-eab`,
   `rotate-trust-sync` ->
   `sync-after-trust-sync` -> `verify-after-trust-sync`,
   `rotate-responder-hmac` ->
   `sync-after-responder-hmac` -> `verify-after-responder-hmac`
8. Confirm certificate fingerprint changes between each verification snapshot

Actual commands (script excerpt):

```bash
# control node: infra-up / init / service-add
bootroot infra up --compose-file "$COMPOSE_FILE"
BOOTROOT_LANG=en printf "y\ny\nn\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" --summary-json "$INIT_SUMMARY_JSON" \
  --auto-generate --show-secrets --eab-kid "$INIT_EAB_KID" \
  --eab-hmac "$INIT_EAB_HMAC"
bootroot service add --service-name "$SERVICE_NAME" --deploy-type daemon \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH"

# remote node: sync
bootroot-remote sync --openbao-url "http://127.0.0.1:8200" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$role_id_path" --secret-id-path "$secret_id_path" \
  --agent-config-path "$REMOTE_AGENT_CONFIG_PATH" \
  --summary-json "$summary_path" --output json

# control node: verify / rotate
bootroot verify --service-name "$SERVICE_NAME" \
  --agent-config "$REMOTE_AGENT_CONFIG_PATH"
bootroot rotate --yes approle-secret-id --service-name "$SERVICE_NAME"
bootroot rotate --yes responder-hmac
```

### 4) remote-delivery E2E scenario (`hosts-all`)

Configuration:

- Same control node/remote node model as above
- Same service set as remote `fqdn-only-hosts`: `edge-proxy` (`daemon`)
- Resolution mode is `hosts-all`
- Temporary `/etc/hosts` entries are added/removed by the script

Purpose:

- Validate the remote-bootstrap end-to-end flow under hosts-based resolution mode
- Catch resolution-specific failures in remote sync and verification phases

Execution steps:

1. Add host entries for `stepca.internal` / `responder.internal`
2. Run all remote-delivery E2E scenario phases
3. Remove temporary host entries in cleanup

Actual commands (script excerpt):

```bash
# run remote lifecycle in hosts-all mode
RESOLUTION_MODE=hosts-all ./scripts/e2e/docker/run-main-remote-lifecycle.sh

# internal host-entry add/remove sequence
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 5) rotation/recovery matrix

Configuration:

- Script: `scripts/e2e/docker/run-rotation-recovery.sh`
- Scenario input defaults to
  `tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json`

#### Service set in this scenario (3 nodes, 8 services total)

- `node-a`: daemon-c1 (daemon), daemon-c2 (daemon), docker-c1 (docker)
- `node-b`: daemon-c3 (daemon), docker-c2 (docker), docker-c3 (docker)
- `node-c`: daemon-c4 (daemon), docker-c4 (docker)

Each service is validated across all rotation items.

#### Rotation items

- `secret_id,eab,responder_hmac,trust_sync`

Purpose:

- Validate state-machine behavior for pending/applied/failed/expired
- Validate targeted failure handling and subsequent recovery
- Validate expiry (`expired`) and re-sync to `applied`

Execution steps (per rotation item):

1. Mark all services `pending`
2. Sync cycle 1: expect `pending -> applied`
3. Sync cycle 2 (re-rotation): expect `pending -> applied`
4. Failure cycle: inject one targeted failure, expect target service `failed`
   or `pending`,
   and expect other services to remain `applied`
5. Recovery cycle: mark target `pending` again, rerun sync, and expect
   `applied`
6. For `secret_id`, also validate forced `expired` via summary+ack, then
   rerun sync and return to `applied`

Actual commands (script excerpt):

```bash
# scenario entrypoint
./scripts/e2e/docker/run-rotation-recovery.sh

# key commands used in sync/ack/verify loops
./scripts/e2e/docker/run-sync-once.sh
bootroot verify --service-name "$service" --agent-config "$agent_config_path"

# force expired and ack it to state
bootroot service sync-status --service-name "$service_name" \
  --summary-json "$summary_path"
```

### 6) extended workflow cases

Configuration:

- Script: `scripts/e2e/docker/run-extended-suite.sh`
- Cases: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`
- Case results are aggregated into `extended-summary.json`
- Service set: inherited from each case's underlying scenario/script and includes
  multi-service cases (for scale/contention and failure/recovery)

Purpose:

- Keep heavier stress/recovery coverage outside PR-critical CI path
- Validate periodic execution mode parity (`systemd-timer` vs `cron`)
- Validate repeatability under higher cycle counts/time windows

Execution steps:

1. Run each case independently and capture per-case `run.log`
2. Mark each case `start/pass/fail` in `phases.log`
3. Aggregate all case results into `extended-summary.json`
4. Fail workflow when any case is `fail`

Actual commands (script excerpt):

```bash
# extended suite entrypoint
./scripts/e2e/docker/run-extended-suite.sh

# internal case dispatch
./scripts/e2e/docker/run-baseline.sh
./scripts/e2e/docker/run-rotation-recovery.sh
RUNNER_MODE=systemd-timer ./scripts/e2e/docker/run-harness-smoke.sh
RUNNER_MODE=cron ./scripts/e2e/docker/run-harness-smoke.sh
```

## Local preflight standard

Before pushing code, run all of these:

1. `cargo test`
2. `./scripts/ci-local-e2e.sh`
3. `./scripts/e2e/docker/run-extended-suite.sh`

Execution guide:

```bash
./scripts/ci-local-e2e.sh
./scripts/e2e/docker/run-extended-suite.sh
```

When local `sudo -n` is unavailable, run:

Reason: `hosts-all` cases add and restore host-machine `/etc/hosts` during the
run, and that operation requires non-interactive admin privileges (`sudo -n`).

- `./scripts/ci-local-e2e.sh --skip-hosts-all`

Use this only as a local constraint workaround. CI still executes
`hosts-all` variants.

## Init automation input/output rules

Lifecycle scripts consume `bootroot init --summary-json` output for automation.
Do not parse human-readable summary lines for tokens/secrets.

Minimum machine field used by E2E:

- `root_token`

How E2E handles OpenBao unseal and token usage:

- E2E typically unseals once during `init` and does not unseal again in the
  same run
- Unseal is required again only after OpenBao returns to `sealed` state
  (for example: process/container restart, manual seal, recovery flow)
- `root_token` is read from `init-summary.json`, stored in a shell variable
  (`OPENBAO_ROOT_TOKEN`), and passed to `service add`/`rotate` in the same run
  via `--root-token`
- Because summary JSON contains the token, treat the artifact as sensitive
  output in storage/retention workflows

Operational guidance:

- treat init summary JSON as sensitive artifact
- avoid printing raw secrets in logs
- keep secret files/dirs with `0600`/`0700` permissions

## Remote sync verification criteria

This section defines how E2E decides whether remote synchronization was
actually applied.

Verification flow:

1. `bootroot service add --delivery-mode remote-bootstrap` on the control node
   records desired state.
2. `bootroot-remote sync` on the remote node reads that state and applies it to
   local files/config. (`sync` includes `pull`/`ack` behavior internally)
3. E2E compares the following two outputs and requires the same result.  
   (1) JSON from `bootroot-remote sync --summary-json ...`  
   (2) state view from `bootroot service sync-status` on the control node

Per-service comparison items:

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

Pass/fail rules:

- item status must match between the two outputs
- in rotation tests, expected transitions (for example `pending -> applied`)
  must appear
- if any item remains `failed` or outputs disagree, the phase fails

Status meanings:

- `none`: item not created/recorded yet
- `pending`: desired state recorded but not applied yet
- `applied`: remote apply completed successfully
- `failed`: apply failed with an error
- `expired`: item age/validity requires re-sync

## E2E `phases.log` format

E2E scripts write step-progress events to `phases.log`.
The examples below describe the JSON event format in that file.

Main lifecycle scripts write:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"fqdn-only-hosts"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: step identifier
- `mode`: resolution mode (`fqdn-only-hosts` or `hosts-all`)

Extended suite writes:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: case identifier
- `status`: `start|pass|fail`

## Artifact locations

For general users, this is not required information.  
For users/contributors debugging CI failures directly, it is useful.

Typical PR-critical artifacts:

- `tmp/e2e/ci-main-fqdn-<run-id>`
- `tmp/e2e/ci-main-hosts-<run-id>`
- `tmp/e2e/ci-main-remote-fqdn-<run-id>`
- `tmp/e2e/ci-main-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

Typical extended artifact:

- `tmp/e2e/extended-<run-id>`

## Failure check order

When a run fails, inspect in this order:

1. `phases.log` (where it stopped)
2. `run.log` (high-level command flow)
3. `init.raw.log` / `init.log` (init-specific failures)
4. `compose-logs.log` or per-case logs (container/service details)
5. `extended-summary.json` (extended suite case-level status)
