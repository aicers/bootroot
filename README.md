# bootroot

[![CI](https://github.com/aicers/bootroot/actions/workflows/ci.yml/badge.svg)](https://github.com/aicers/bootroot/actions/workflows/ci.yml)

**bootroot** is a product-embedded PKI bootstrap and trust foundation.
It uses **OpenBao** to manage secrets and provides a CLI-first workflow to
bring up a private CA and issue/renew mTLS certificates.

**bootroot** is the umbrella name for:

- **bootroot CLI** (`bootroot`)
- **bootroot-agent** (`bootroot-agent`)
- **bootroot-remote** (`bootroot-remote`)
- **HTTP-01 responder** (`bootroot-http01-responder`)
- **Prometheus** (monitoring)
- **Grafana** (monitoring dashboards)

Open source dependencies:

- **step-ca**: ACME-compatible private CA
- **OpenBao**: secret manager (Vault-compatible KV v2)
- **PostgreSQL**: step-ca database
- **Prometheus**: metrics collection
- **Grafana**: metrics visualization

## Architecture Summary

- **Single-machine default**: `bootroot infra up` starts OpenBao, PostgreSQL,
  step-ca, and the HTTP-01 responder with Docker Compose on the step-ca host.
- **Monitoring**: Prometheus scrapes step-ca/OpenBao metrics and Grafana
  visualizes them for local ops.
- **Service onboarding**: `bootroot service add` registers service metadata,
  creates an AppRole, and prints the run instructions for bootroot-agent and
  OpenBao Agent.
- **Certificate flow**: bootroot-agent issues/renews certs; OpenBao Agent
  renders secrets and config files for each service.

For multi-machine or manual deployment, follow the manual guides in `docs/`.

## Quick Start (CLI)

See `docs/en/cli.md` (EN) or `docs/ko/cli.md` (KO) for the full flow.

Typical sequence:

```bash
bootroot infra up
bootroot init
bootroot service add
bootroot verify
bootroot rotate ...
bootroot monitoring up|status|down
```

## Documentation

- Design philosophy: [`DESIGN.md`](DESIGN.md)
- Manual entry point: [`docs/en/index.md`](docs/en/index.md) (English)
- 매뉴얼 시작점: [`docs/ko/index.md`](docs/ko/index.md) (한국어)
- CLI guide (EN): [`docs/en/cli.md`](docs/en/cli.md)
- CLI guide (KO): [`docs/ko/cli.md`](docs/ko/cli.md)

For detailed architecture, installation, configuration, and operations
guides, refer to the manuals above.

Build locally:

```bash
brew install python
python3 -m venv .venv
# zsh/bash:
source .venv/bin/activate
# fish:
source .venv/bin/activate.fish
pip install mkdocs-material mkdocs-static-i18n
mkdocs serve -a 127.0.0.1:8000 --livereload --dirtyreload
```

Command notes:

- `brew install python`: installs Python (one-time per machine).
- `python3 -m venv .venv`: creates a local virtualenv for this repo.
- `source .venv/bin/activate`: activates the virtualenv for the current shell.
- `pip install ...`: installs MkDocs tooling into the virtualenv.
- Run the `pip install ...` step once after creating the virtualenv (per clone).
- `mkdocs serve -a 127.0.0.1:8000 --livereload --dirtyreload`: runs a local docs
  server.
- `mkdocs build`: builds static files into `site/`.
- `./scripts/build-docs-pdf.sh en|ko`: builds PDF manuals.

## Docs Authoring Rules (list hierarchy)

To avoid rendered list hierarchy regressions in MkDocs Material:

- Prefer heading/label + single-level list over deep nested lists.
- If nesting is required, use 4-space indentation consistently.
- Keep a blank line before and after nested lists.
- Avoid mixing long free-form paragraphs between list markers where possible.
- For complex comparisons, prefer short table or separate subsection blocks.

Docs PR quick checklist:

- Run local preview for changed docs pages:
  `mkdocs serve -a 127.0.0.1:8000 --livereload --dirtyreload`
- Run markdown lint:
  `markdownlint-cli2 "**/*.md" "#node_modules" "#target"`
- If both KR/EN pages were changed, verify wording/structure parity.

## Quality Checks

Run quality gates locally before pushing:

```bash
cargo fmt -- --check --config group_imports=StdExternalCrate
cargo clippy --all-targets -- -D warnings
biome ci --error-on-warnings .
markdownlint-cli2 "**/*.md" "#node_modules" "#target"
ruff format --check .
ruff check .
cargo audit
cargo test
```

If Python formatting/linting fails, auto-fix first:

```bash
ruff format .
ruff check --fix .
```

## Local E2E Preflight (required before push)

To reduce avoidable CI failures, run the local E2E preflight below in addition
to `cargo test`:

```bash
./scripts/ci-local-e2e.sh
./scripts/e2e/docker/run-extended-suite.sh
```

Why both:

- `./scripts/ci-local-e2e.sh` mirrors the core Docker E2E matrix used by CI
  (main lifecycle, main remote lifecycle, and rotation/recovery).
- `./scripts/e2e/docker/run-extended-suite.sh` covers the extended scenarios
  used by the separate Extended workflow.

If these do not pass locally, CI/Extended workflow failures are likely after
push.

Notes:

- If your machine cannot run non-interactive sudo (`sudo -n`) for `hosts-all`,
  use `./scripts/ci-local-e2e.sh --skip-hosts-all`.
- Artifacts are written under `tmp/e2e/` for triage.

Install scope:

- If you use a per-repo virtualenv (`.venv`), you need to create it and
  install dependencies each time you clone the repo.
- If you install MkDocs globally, it is a one-time machine install, but we
  recommend the per-repo virtualenv to avoid version conflicts.

## Local Scenario Tests

We keep a local end-to-end scenario script that exercises the happy paths and
failure cases across step-ca, PostgreSQL, OpenBao, the HTTP-01 responder, and
bootroot-agent.

Run it from the repo root:

```bash
./scripts/run-local-scenarios.sh happy
```

Script notes:

- `happy` runs the happy-path scenarios (this is what CI uses).
- `all` runs every scenario, including failure cases.
- `TIMEOUT_SECS=180` and `TMP_DIR=./tmp/scenarios` can be overridden as needed.
- The script expects Docker + Compose and uses the local Compose stack.
- Monitoring integration tests (via `cargo test`) require Docker and bind
  Grafana to `127.0.0.1:3000` during the run.

## License

Copyright 2026 ClumL Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.
You may obtain a copy of the License in the `LICENSE` file.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the `LICENSE` file for the specific language governing permissions
and limitations under the License.
