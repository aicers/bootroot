# CI & E2E

This page explains bootroot CI/E2E validation structure, scenario execution
flows, local preflight steps, and failure check criteria.

## CI workflow layout

PR-critical CI (`.github/workflows/ci.yml`) runs:

- `test-core`: unit/integration smoke path
- `test-docker-e2e-matrix`: Docker E2E test set for end-to-end flow +
  rotation/recovery (5 scenarios run in parallel via matrix strategy)

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
  service-node `bootroot-remote bootstrap`.

Host name mapping mode (E2E run mode):

- `fqdn-only-hosts`: an E2E script mode name. It does not modify host-machine
  `/etc/hosts`; it connects to step-ca and responder via `localhost`/IP.
- `hosts-all`: an E2E script mode name. It adds host-machine `/etc/hosts`
  entries for `stepca.internal` and `responder.internal`, then connects by
  those names. In E2E, entries are added during the run and removed in cleanup;
  in production, DNS/hosts must be managed continuously.

Common behavior: both mapping modes add service FQDN -> responder IP mappings
in the step-ca container `/etc/hosts` so SAN targets are reachable.

Operational note: host-entry add/remove behavior in E2E is for test
convenience. In production, maintain DNS/hosts mappings and always-on runtime
state for services/agents continuously.

## Docker E2E test scope

PR-critical Docker test set validates:

- local-delivery E2E scenario (`fqdn-only-hosts`)
- local-delivery E2E scenario (`hosts-all`)
- remote-delivery E2E scenario (`fqdn-only-hosts`)
- remote-delivery E2E scenario (`hosts-all`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac`)

Primary scripts:

- `scripts/impl/run-main-lifecycle.sh`
- `scripts/impl/run-main-remote-lifecycle.sh`
- `scripts/impl/run-rotation-recovery.sh`

Extended workflow validates:

- baseline scale/contention behavior
- repeated failure/recovery behavior
- rotation scheduling parity (`systemd-timer`, `cron`)

Primary script:

- `scripts/impl/run-extended-suite.sh`

## Scenario details and execution steps

This section repeats key context from other manual pages on purpose.
Use this page alone as an operational guide for CI/E2E understanding and
reproduction.

### 1) local-delivery E2E scenario (`fqdn-only-hosts`)

Configuration:

- Single machine baseline used by `scripts/impl/run-main-lifecycle.sh`
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
2. `init`: run `bootroot init --summary-json` and read runtime AppRole
   credentials from JSON
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
# from init summary
#   runtime_service_add: role_id/secret_id
#   runtime_rotate: role_id/secret_id
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
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
RESOLUTION_MODE=hosts-all ./scripts/impl/run-main-lifecycle.sh

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
- Remote bootstrap apply is executed by `bootroot-remote bootstrap`
- Resolution mode is `fqdn-only-hosts`

Purpose:

- Validate remote-bootstrap onboarding and one-shot bootstrap apply mode
- Validate bootstrap-driven updates for
  `secret_id`, `eab`, `responder_hmac`
- Validate remote rotation/recovery sequence and explicit secret_id handoff

Execution steps:

1. `infra-up`, `init` on control node, then parse runtime AppRole credentials
   from summary JSON
2. `service-add` in `remote-bootstrap` mode (control node writes desired state)
3. Copy bootstrap materials (`role_id`, `secret_id`) to remote node
4. `bootstrap-initial`: run `bootroot-remote bootstrap` on remote node
5. `verify-initial`: issue/verify certificate on remote node
6. Rotation + apply-secret-id + verify cycles:
   `rotate-secret-id` -> `apply-secret-id` -> `verify-after-secret-id`,
   `rotate-eab` -> `verify-after-eab`,
   `rotate-responder-hmac` -> `verify-after-responder-hmac`
7. Confirm certificate fingerprint changes between each verification snapshot

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

# remote node: bootstrap
bootroot-remote bootstrap --openbao-url "http://127.0.0.1:8200" \
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
    - Add `stepca.internal` entry
    - Add `responder.internal` entry
2. Run all remote-delivery E2E scenario phases
3. Remove temporary host entries in cleanup
    - Remove only lines tagged with `HOSTS_MARKER`

Actual commands (script excerpt):

```bash
# run remote lifecycle in hosts-all mode
RESOLUTION_MODE=hosts-all ./scripts/impl/run-main-remote-lifecycle.sh

# internal host-entry add/remove sequence
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 5) rotation/recovery matrix

Configuration:

- Script: `scripts/impl/run-rotation-recovery.sh`
- Scenario input defaults to
  `tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json`

#### Service set in this scenario (3 nodes, 8 services total)

- `node-a`: daemon-c1 (daemon), daemon-c2 (daemon), docker-c1 (docker)
- `node-b`: daemon-c3 (daemon), docker-c2 (docker), docker-c3 (docker)
- `node-c`: daemon-c4 (daemon), docker-c4 (docker)

Each service is validated across all rotation items.

#### Rotation items

- `secret_id,eab,responder_hmac`

Purpose:

- Validate rotation and recovery behavior per item
- Validate targeted failure handling and subsequent recovery
- Validate explicit secret_id handoff via `bootroot-remote apply-secret-id`

Execution steps (per rotation item):

1. Rotate target item on control node
2. For `secret_id`: run `bootroot-remote apply-secret-id` on remote node
3. Verify certificate issuance still works after rotation
4. Failure cycle: inject one targeted failure and verify recovery
5. Recovery cycle: re-rotate and re-apply, confirm normal operation

Actual commands (script excerpt):

```bash
# scenario entrypoint
./scripts/impl/run-rotation-recovery.sh

# key commands used in rotation/verify loops
bootroot rotate --yes approle-secret-id --service-name "$service"
bootroot-remote apply-secret-id --service-name "$service" ...
bootroot verify --service-name "$service" --agent-config "$agent_config_path"
```

### 6) extended workflow cases

Configuration:

- Script: `scripts/impl/run-extended-suite.sh`
- Cases: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`
- Case results are aggregated into `extended-summary.json`
- Service set: inherited from each case's underlying scenario/script and includes
  multi-service cases (for scale/contention and failure/recovery)

Purpose:

- Keep heavier stress/recovery coverage outside PR-critical CI path
- Validate rotation scheduling parity (`systemd-timer` vs `cron`)
- Validate repeatability under higher cycle counts/time windows

Execution steps:

1. Run each case independently and capture per-case `run.log`
2. Mark each case `start/pass/fail` in `phases.log`
3. Aggregate all case results into `extended-summary.json`
4. Fail workflow when any case is `fail`

Actual commands (script excerpt):

```bash
# extended suite entrypoint
./scripts/impl/run-extended-suite.sh

# internal case dispatch
./scripts/impl/run-baseline.sh
./scripts/impl/run-rotation-recovery.sh
RUNNER_MODE=systemd-timer ./scripts/impl/run-harness-smoke.sh
RUNNER_MODE=cron ./scripts/impl/run-harness-smoke.sh
```

## Local preflight standard

Before pushing code, run all preflight checks:

```bash
./scripts/preflight/run-all.sh
```

Or run individual scripts:

| Script | CI job |
| --- | --- |
| `./scripts/preflight/ci/check.sh` | `ci.yml` Quality Check |
| `./scripts/preflight/ci/test-core.sh` | `ci.yml` Test Suite (Core) |
| `./scripts/preflight/ci/e2e-matrix.sh` | `ci.yml` Docker E2E Matrix |
| `./scripts/preflight/ci/e2e-extended.sh` | `e2e-extended.yml` Run Extended |

Local-only extras (not in any CI workflow):

| Script | Description |
| --- | --- |
| `./scripts/preflight/extra/agent-scenarios.sh` | Agent scenario tests |
| `./scripts/preflight/extra/cli-scenarios.sh` | CLI scenario tests |

When local `sudo -n` is unavailable:

- Run `./scripts/preflight/ci/e2e-matrix.sh --skip-hosts-all`.
- Reason: `hosts-all` cases add and restore host-machine `/etc/hosts` during
  the run, and that operation requires non-interactive admin privileges
  (`sudo -n`).

Use this only as a local constraint workaround. CI still executes
`hosts-all` variants.

## Init automation input/output rules

Lifecycle scripts consume `bootroot init --summary-json` output for automation.
Do not parse human-readable summary lines for tokens/secrets.
Local CLI scenario runs use the same rule and read runtime AppRole credentials
from `.approles[]` in `--summary-json`.
This is a **test/automation convenience rule**, not a production token custody
policy.

Minimum machine fields used by E2E:

- `.approles[]` entries for:
  - `runtime_service_add` (`role_id`, `secret_id`)
  - `runtime_rotate` (`role_id`, `secret_id`)

How E2E handles OpenBao unseal and runtime auth:

- E2E typically unseals once during `init` and does not unseal again in the
  same run
- Unseal is required again only after OpenBao returns to `sealed` state
  (for example: process/container restart, manual seal, recovery flow)
- runtime AppRole credentials are read from `init-summary.json` (`approles`)
  and passed to `service add`/`rotate` via `--auth-mode approle`
- scripts avoid long-term credential persistence; values stay in per-run shell
  context
- summary JSON contains sensitive fields (including root token and AppRole
  secret_id), so treat the artifact as sensitive in retention workflows

Operational guidance:

- treat init summary JSON as sensitive artifact
- avoid printing raw secrets in logs
- keep secret files/dirs with `0600`/`0700` permissions

## Remote bootstrap verification criteria

This section defines how E2E decides whether remote bootstrap was
actually applied.

Verification flow:

1. `bootroot service add --delivery-mode remote-bootstrap` on the control node
   records desired state.
2. `bootroot-remote bootstrap` on the remote node reads that state and applies
   it to local files/config.
3. E2E verifies the bootstrap summary JSON output shows all items as `applied`.

Per-service verification items:

- `secret_id`
- `eab`
- `responder_hmac`

Pass/fail rules:

- all bootstrap items must show `applied` in the summary output
- after secret_id rotation, `bootroot-remote apply-secret-id` must complete
  successfully
- if any item shows `failed`, the phase fails

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
