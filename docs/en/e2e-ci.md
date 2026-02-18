# CI & E2E

This page explains how bootroot validates behavior in CI and how to reproduce
the same checks locally.

## Pipeline model

PR-critical CI (`.github/workflows/ci.yml`) runs:

- `test-core`: unit/integration smoke path
- `test-docker-e2e-matrix`: Docker E2E matrix for lifecycle + rotation/recovery

Extended E2E (`.github/workflows/e2e-extended.yml`) runs separately:

- `workflow_dispatch` (manual trigger)
- scheduled trigger at `23:30 KST` (UTC cron), gated by same-day `main` commit
  activity (KST)

The extended workflow is for heavier resilience/stress coverage and is kept
outside the PR-critical path.

## Docker E2E coverage

PR-critical Docker matrix validates:

- main lifecycle (`fqdn-only-hosts`)
- main lifecycle (`hosts-all`)
- main remote lifecycle (`fqdn-only-hosts`)
- main remote lifecycle (`hosts-all`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)

Primary scripts:

- `scripts/e2e/docker/run-main-lifecycle.sh`
- `scripts/e2e/docker/run-main-remote-lifecycle.sh`
- `scripts/e2e/docker/run-rotation-recovery.sh`

Extended workflow validates:

- baseline scale/contention behavior
- repeated failure/recovery behavior
- runner mode parity (`systemd-timer`, `cron`)

Primary script:

- `scripts/e2e/docker/run-extended-suite.sh`

## Local preflight standard

Before pushing code, run all of these:

1. `cargo test`
2. `./scripts/ci-local-e2e.sh`
3. `./scripts/e2e/docker/run-extended-suite.sh`

When local `sudo -n` is unavailable, run:

- `./scripts/ci-local-e2e.sh --skip-hosts-all`

Use this only as a local constraint workaround. CI still executes
`hosts-all` variants.

## Init automation contract

Lifecycle scripts consume `bootroot init --summary-json` output for automation.
Do not parse human-readable summary lines for tokens/secrets.

Minimum machine field used by E2E:

- `root_token`

Operational guidance:

- treat init summary JSON as sensitive artifact
- avoid printing raw secrets in logs
- keep secret files/dirs with `0600`/`0700` permissions

## bootroot-remote sync contract

Remote convergence is validated through:

- `bootroot-remote pull`
- `bootroot-remote ack`
- `bootroot-remote sync`

Sync summary JSON and `bootroot service sync-status` must align on these
items:

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

Status lifecycle values:

- `none`
- `pending`
- `applied`
- `failed`
- `expired`

## Phase log schema

Main lifecycle scripts produce phase events:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"fqdn-only-hosts"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: step identifier
- `mode`: resolution mode (`fqdn-only-hosts` or `hosts-all`)

Extended suite produces phase events:

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

Fields:

- `ts`: UTC timestamp
- `phase`: case identifier
- `status`: `start|pass|fail`

## Artifact locations

Typical PR-critical artifacts:

- `tmp/e2e/ci-main-fqdn-<run-id>`
- `tmp/e2e/ci-main-hosts-<run-id>`
- `tmp/e2e/ci-main-remote-fqdn-<run-id>`
- `tmp/e2e/ci-main-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

Typical extended artifact:

- `tmp/e2e/extended-<run-id>`

## Triage order

When a run fails, inspect in this order:

1. `phases.log` (where it stopped)
2. `run.log` (high-level command flow)
3. `init.raw.log` / `init.log` (init-specific failures)
4. `compose-logs.log` or per-case logs (container/service details)
5. `extended-summary.json` (extended suite case-level status)

## Reproduction commands

Local PR-critical matrix:

```bash
./scripts/ci-local-e2e.sh
```

Local extended suite:

```bash
./scripts/e2e/docker/run-extended-suite.sh
```

Full quality gates (before E2E):

```bash
cargo fmt -- --check --config group_imports=StdExternalCrate
cargo clippy --all-targets -- -D warnings
biome ci --error-on-warnings .
cargo audit
markdownlint-cli2 "**/*.md" "#node_modules" "#target"
```
