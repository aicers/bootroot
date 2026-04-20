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

- `no-hosts`: an E2E script mode name. It does not modify host-machine
  `/etc/hosts`; it connects to step-ca and responder via `localhost`/IP.
- `hosts`: an E2E script mode name. It adds host-machine `/etc/hosts`
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

- local-delivery E2E scenario (`no-hosts`)
- local-delivery E2E scenario (`hosts`)
- remote-delivery E2E scenario (`no-hosts`)
- remote-delivery E2E scenario (`hosts`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)

Primary scripts:

- `scripts/impl/run-local-lifecycle.sh`
- `scripts/impl/run-remote-lifecycle.sh`
- `scripts/impl/run-rotation-recovery.sh`

Extended workflow validates:

- baseline scale/contention behavior
- repeated failure/recovery behavior
- rotation scheduling parity (`systemd-timer`, `cron`)
- CA key rotation failure/recovery (5 failure injection scenarios)
- infra lifecycle (full local-delivery round-trip)

Primary script:

- `scripts/impl/run-extended-suite.sh`

## Scenario details and execution steps

This section repeats key context from other manual pages on purpose.
Use this page alone as an operational guide for CI/E2E understanding and
reproduction.

### 1) local-delivery E2E scenario (`no-hosts`)

Configuration:

- Single machine baseline used by `scripts/impl/run-local-lifecycle.sh`
- `openbao`, `postgres`, `step-ca`, `bootroot-http01` run in Docker Compose
- Services are added with `--delivery-mode local-file`
- Service set in this scenario (2 services): `edge-proxy` (`daemon`),
  `web-app` (`docker`)
- Resolution mode is `no-hosts` (no `/etc/hosts` mutation)

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
5. `rotate-openbao-recovery`: manually rotate OpenBao root token
6. `bootstrap-after-openbao-recovery`: re-run remote bootstrap and verify
   AppRole-based access continuity
7. `rotate-responder-hmac`: run rotation and force reissue
8. `verify-after-responder-hmac`: verify certs again and confirm fingerprint changes
9. `cleanup`: capture logs/artifacts and tear down Compose

Actual commands (script excerpt):

```bash
# 1) infra-install (generates .env, starts containers)
bootroot infra install --compose-file "$COMPOSE_FILE"

# 2) init
# DB credentials are read from .env created by infra install.
# POSTGRES_HOST and POSTGRES_PORT are set by the script so that
# build_admin_dsn_from_env() connects via the host-mapped port.
BOOTROOT_LANG=en printf "y\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" \
  --secrets-dir "$SECRETS_DIR" \
  --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets,db-provision \
  --db-user "step" \
  --db-name "stepca" \
  --responder-url "$RESPONDER_URL"

# 3) service-add
bootroot service add --service-name edge-proxy --deploy-type daemon \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"
bootroot service add --service-name web-app --deploy-type docker \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"

# 4) verify-initial / 8) verify-after-responder-hmac
bootroot verify --service-name edge-proxy --agent-config "$AGENT_CONFIG_PATH"
bootroot verify --service-name web-app --agent-config "$AGENT_CONFIG_PATH"

# 5) rotate-openbao-recovery (manual, explicit operator action)
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --root-token "$INIT_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-root-token \
  --output "$OPENBAO_RECOVERY_OUTPUT_FILE"

# 7) rotate-responder-hmac
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

### 2) local-delivery E2E scenario (`hosts`)

Configuration:

- Same script and same-machine topology as above
- Same service set as `no-hosts`: `edge-proxy` (`daemon`), `web-app` (`docker`)
- Resolution mode is `hosts`
- Script writes temporary `stepca.internal` / `responder.internal` host entries
  (requires `sudo -n`)

Purpose:

- Validate hostname-based resolution path used by `hosts`
- Catch breakage tied to `/etc/hosts`-driven name resolution

Execution steps:

1. Add host entries for `stepca.internal` and `responder.internal`
2. Run the same end-to-end flow phases as `no-hosts`
3. Remove temporary host entries during cleanup

Actual commands (script excerpt):

```bash
# run in hosts mode
RESOLUTION_MODE=hosts ./scripts/impl/run-local-lifecycle.sh

# internal host-entry add/remove sequence
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 3) remote-delivery E2E scenario (`no-hosts`)

Configuration:

- Two workspaces in one run: `control node` (step-ca machine role),
  `remote node` (service machine role)
- Services are added with `--delivery-mode remote-bootstrap`
- Service set in this scenario (2 services): `edge-proxy` (`daemon`),
  `web-app` (`docker`)
- Remote bootstrap apply is executed by `bootroot-remote bootstrap`
- Resolution mode is `no-hosts`

Purpose:

- Validate remote-bootstrap onboarding and one-shot bootstrap apply mode
- Validate bootstrap-driven updates for `eab`, `trust_sync`, `responder_hmac`
  (the `eab` item covers the operator-provided pass-through: the harness
  writes EAB credentials to OpenBao KV directly and verifies that
  `bootroot-remote bootstrap` applies them)
- Validate `secret_id` rotation delivery (in production, operators use
  `bootroot-remote apply-secret-id`; the E2E test uses `bootstrap` for
  uniformity since the old `secret_id` is still valid during the test window)
- Validate remote rotation/recovery sequence

Execution steps:

1. `infra-up`, `init` on control node, then parse runtime AppRole credentials
   from summary JSON
2. `service-add` in `remote-bootstrap` mode for both services
3. Copy bootstrap materials (`role_id`, `secret_id`) to remote node
4. `bootstrap-initial`: run `bootroot-remote bootstrap` on remote node
   for each service
5. `verify-initial`: issue/verify certificates on remote node
6. Rotation + bootstrap re-apply + verify cycles:
   `rotate-secret-id` -> `bootstrap` -> `verify-after-secret-id`,
   `rotate-trust-sync` -> `bootstrap` -> `verify-after-trust-sync`,
   `rotate-responder-hmac` -> `bootstrap` -> `verify-after-responder-hmac`
7. Confirm certificate fingerprint changes between each verification snapshot

Actual commands (script excerpt):

```bash
# control node: infra-install / init / service-add
bootroot infra install --compose-file "$COMPOSE_FILE"
BOOTROOT_LANG=en printf "y\ny\nn\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets --eab-kid "$INIT_EAB_KID" \
  --eab-hmac "$INIT_EAB_HMAC"
bootroot service add --service-name edge-proxy --deploy-type daemon \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH"
bootroot service add --service-name web-app --deploy-type docker \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH_2"

# remote node: bootstrap (per service)
bootroot-remote bootstrap --openbao-url "http://127.0.0.1:8200" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$role_id_path" --secret-id-path "$secret_id_path" \
  --agent-config-path "$REMOTE_AGENT_CONFIG_PATH" \
  --output json

# control node: rotate / remote node: re-apply via bootstrap
bootroot rotate --yes approle-secret-id --service-name edge-proxy
bootroot rotate --yes approle-secret-id --service-name web-app
bootroot-remote bootstrap ...  # re-apply for each service
bootroot rotate --yes responder-hmac
bootroot-remote bootstrap ...  # re-apply for each service
```

### 4) remote-delivery E2E scenario (`hosts`)

Configuration:

- Same control node/remote node model as above
- Same service set as remote `no-hosts`: `edge-proxy` (`daemon`),
  `web-app` (`docker`)
- Resolution mode is `hosts`
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
# run remote lifecycle in hosts mode
RESOLUTION_MODE=hosts ./scripts/impl/run-remote-lifecycle.sh

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

- `secret_id,eab,responder_hmac,trust_sync`

Purpose:

- Validate rotation and recovery behavior per item
- Validate targeted failure handling and subsequent recovery
- Validate re-apply after each rotation

> **Note:** The E2E test uses `bootroot-remote bootstrap` to re-apply all
> rotation items uniformly (including `secret_id`). This works because the
> old `secret_id` remains valid during the test window and both `bootstrap`
> and `apply-secret-id` authenticate the same way. In production, the
> recommended path for `secret_id`-only rotation is
> `bootroot-remote apply-secret-id` (see the operations guide).

Execution steps (per rotation item):

1. Rotate target item on control node
2. Run `bootroot-remote bootstrap` on each remote node to re-apply
3. Verify certificate issuance still works after rotation
4. Failure cycle: inject one targeted failure and verify recovery
5. Recovery cycle: re-rotate and re-apply, confirm normal operation

Actual commands (script excerpt):

```bash
# scenario entrypoint
./scripts/impl/run-rotation-recovery.sh

# key commands used in rotation/verify loops
bootroot rotate --yes approle-secret-id --service-name "$service"
bootroot-remote bootstrap --service-name "$service" ...
bootroot verify --service-name "$service" --agent-config "$agent_config_path"
```

### 6) CA key rotation failure/recovery

Configuration:

- Script: `scripts/impl/run-ca-key-rotation-recovery.sh`
- Single machine baseline with Docker Compose infra
- Service set (3 services): `edge-proxy` (`daemon`, `local-file`),
  `web-app` (`docker`, `local-file`), `edge-proxy` (`daemon`,
  `remote-bootstrap`)
- 5 failure injection scenarios run sequentially on the same infra

Purpose:

- Validate that `bootroot rotate ca-key` resumes correctly after
  infrastructure failures at each phase
- Validate that mTLS is never disrupted during CA key rotation
- Validate `rotation-state.json` idempotent phase tracking
- Validate `--skip reissue`, `--force`, `--cleanup` flag behaviors
- Validate `trust-sync` conflict guard during active rotation

#### Scenarios

Scenario 1 — Phase 3 failure (OpenBao unreachable):

1. Stop OpenBao container so Phase 3 (additive trust write) fails
2. Run `rotate ca-key` — expect failure
3. Verify services still work (certs unchanged, step-ca running)
4. Restart OpenBao, re-run rotation — resumes and completes
5. Force-reissue and verify new certificates

Scenario 2 — Phase 4 failure (step-ca removed):

1. Remove step-ca container so Phase 4 (restart) fails
2. Run `rotate ca-key` — Phases 0-3 succeed, Phase 4 fails
3. Verify services still work (transitional trust active)
4. Bring step-ca back, re-run rotation — resumes and completes
5. Force-reissue and verify new certificates

Scenario 3 — Phase 5 partial re-issuance:

1. Run `rotate ca-key --skip reissue` — Phase 6 bails (unmigrated)
2. Force-reissue only one service (edge-proxy)
3. Verify both old-cert (web-app) and new-cert (edge-proxy) work
4. Force-reissue remaining services
5. Re-run rotation with `--force` — completes

Scenario 4 — Phase 6 entry blocked:

1. Run `rotate ca-key --skip reissue` — Phase 6 blocks
2. Verify error output mentions un-migrated service names
3. Re-run with `--force` — Phase 6 completes with warning
4. Force-reissue and verify

Scenario 5 — trust-sync conflict during active rotation:

1. Create active rotation by stopping step-ca mid-rotation
2. Verify `rotation-state.json` exists
3. Run `trust-sync` — expect abort with rotation-in-progress error
4. Recover: bring step-ca back, complete rotation
5. Verify all services

Actual commands (script excerpt):

```bash
# wrapper for rotate ca-key with AppRole auth
bootroot rotate \
  --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://${STEPCA_HOST_IP}:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes \
  ca-key --skip reissue --force --cleanup

# failure injection via Docker manipulation
docker compose -f "$COMPOSE_FILE" stop openbao
docker compose -f "$COMPOSE_FILE" rm -sf step-ca
```

### 7) extended workflow cases

Configuration:

- Script: `scripts/impl/run-extended-suite.sh`
- Cases: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`,
  `ca-key-recovery`, `infra-lifecycle`
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
./scripts/impl/run-ca-key-rotation-recovery.sh
./scripts/impl/run-local-lifecycle.sh
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
| `./scripts/preflight/ci/test-core.sh` | `ci.yml` Unit & CLI Smoke |
| `./scripts/preflight/ci/e2e-matrix.sh` | `ci.yml` Docker E2E Matrix |
| `./scripts/preflight/ci/e2e-extended.sh` | `e2e-extended.yml` Run Extended |

Local-only extras (not in any CI workflow):

| Script | Description |
| --- | --- |
| `./scripts/preflight/extra/agent-scenarios.sh` | Agent scenario tests |
| `./scripts/preflight/extra/cli-scenarios.sh` | CLI scenario tests |

When local `sudo -n` is unavailable:

- Run `./scripts/preflight/ci/e2e-matrix.sh --skip-hosts`.
- Reason: `hosts` cases add and restore host-machine `/etc/hosts` during
  the run, and that operation requires non-interactive admin privileges
  (`sudo -n`).

Use this only as a local constraint workaround. CI still executes
`hosts` variants.

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
- `eab` (reports `skipped` when the operator has not provisioned EAB
  credentials, which is the default for the bundled OSS step-ca topology)
- `responder_hmac`
- `trust_sync`

Pass/fail rules:

- each required bootstrap item must show `applied`, `unchanged`, or
  `skipped` (EAB only) in the summary output
- after rotation, re-apply must complete successfully (`bootstrap` in
  E2E; `apply-secret-id` for `secret_id`-only rotation in production)
- if any item shows `failed`, the phase fails

## E2E `phases.log` format

E2E scripts write step-progress events to `phases.log`.
The examples below describe the JSON event format in that file.

Lifecycle scripts write:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"no-hosts"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: step identifier
- `mode`: resolution mode (`no-hosts` or `hosts`)

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

- `tmp/e2e/ci-local-no-hosts-<run-id>`
- `tmp/e2e/ci-local-hosts-<run-id>`
- `tmp/e2e/ci-remote-no-hosts-<run-id>`
- `tmp/e2e/ci-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

Typical extended artifacts:

- `tmp/e2e/extended-<run-id>` (contains per-case subdirectories including
  `ca-key-recovery/`, `infra-lifecycle/`, etc.)

## Failure check order

When a run fails, inspect in this order:

1. `phases.log` (where it stopped)
2. `run.log` (high-level command flow)
3. `init.raw.log` / `init.log` (init-specific failures)
4. `compose-logs.log` or per-case logs (container/service details)
5. `extended-summary.json` (extended suite case-level status)
