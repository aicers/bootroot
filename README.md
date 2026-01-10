# bootroot

[![CI](https://github.com/aicers/bootroot/actions/workflows/ci.yml/badge.svg)](https://github.com/aicers/bootroot/actions/workflows/ci.yml)

**bootroot** is a product-embedded PKI bootstrap and trust foundation.
It provides a robust **Rust-based ACME Agent** that automates certificate
issuance and renewal from an ACME-compatible Private CA (like `step-ca`).

## Features

- **ACME Client**: Fully compliant RFC 8555 implementation (Rust).
- **Supports**: `step-ca` (Internal CA) and `Pebble` (Testing).
- **Security**: ECSDA P-256 keys, secure storage, and minimal dependencies.
- **Deployment**: Single static binary or lightweight Docker image.
- **Daemon Mode**: Periodic renewal checks with graceful shutdown.
- **Documentation**: Bilingual manual skeleton (EN/KR) via MkDocs.

## Documentation

- Manual entry point: `docs/en/index.md` (English)
- 매뉴얼 시작점: `docs/ko/index.md` (한국어)

Build locally:

```bash
brew install python
python3 -m venv .venv
# zsh/bash:
source .venv/bin/activate
# fish:
source .venv/bin/activate.fish
pip install mkdocs-material mkdocs-static-i18n
mkdocs serve -a 127.0.0.1:8000
```

Command notes:

- `brew install python`: installs Python (one-time per machine).
- `python3 -m venv .venv`: creates a local virtualenv for this repo.
- `source .venv/bin/activate`: activates the virtualenv for the current shell.
- `pip install ...`: installs MkDocs tooling into the virtualenv.
- Run the `pip install ...` step once after creating the virtualenv (per clone).
- `mkdocs serve -a 127.0.0.1:8000`: runs a local docs server.
- `mkdocs build`: builds static files into `site/`.
- `./scripts/build-docs-pdf.sh en|ko`: builds PDF manuals.

Install scope:

- If you use a per-repo virtualenv (`.venv`), you need to create it and
  install dependencies each time you clone the repo.
- If you install MkDocs globally, it is a one-time machine install, but we
  recommend the per-repo virtualenv to avoid version conflicts.

## Local Scenario Tests

We keep a local end-to-end scenario script that exercises the happy paths and
failure cases across step-ca, PostgreSQL, the HTTP-01 responder, and the agent.

Run it from the repo root:

```bash
./scripts/run-local-scenarios.sh happy
```

Script notes:

- `happy` runs the five happy-path scenarios (this is what CI uses).
- `all` runs every scenario, including failure cases.
- `TIMEOUT_SECS=180` and `TMP_DIR=./tmp/scenarios` can be overridden as needed.
- The script expects Docker + Compose and uses the local Compose stack.

## Getting Started

### Prerequisites

- **Rust** (latest stable)
- **Docker** & **Docker Compose**
- **Biome** (`brew install biome`) for development.

### Quick Start (Docker)

This is the easiest way to verify the agent and CA integration.

Before you start, ensure the auto-generated DNS SAN resolves from step-ca to
the HTTP-01 responder. In Compose, `bootroot-http01` provides the
`001.bootroot-agent.bootroot-agent.trusted.domain` alias. If you change
`domain` in `agent.toml.compose`, update the alias in `docker-compose.yml` or
map it in step-ca `/etc/hosts`. The recommended naming scheme is
`<instance-id>.<daemon-name>.<hostname>.<domain>`.

1. **Start Services**

   The repository comes with pre-generated test secrets in `secrets/`.
   The Compose stack runs `step-ca` with a local PostgreSQL backend
   (password auth enabled for dev) and builds a custom `step-ca` binary
   with PostgreSQL support.
   For now the DB password lives in `.env` for local dev. If you change
   `POSTGRES_PASSWORD`, update `secrets/config/ca.json` to match the new
   password in `db.dataSource` (or run `scripts/update-ca-db-dsn.sh`).
   Secret Manager integration (e.g., OpenBao) will be added later.

   ```bash
   docker compose up --build -d
   ```

2. **Verify Certificate Issuance**

   Check the agent logs for success message:

   ```bash
   docker logs -f bootroot-agent
   # Expected output: "Successfully issued certificate!"
   ```

3. **Check Artifacts**

   The issued certificate and key are saved to `./certs/`:

   ```bash
   ls -l certs/
   # bootroot-agent.crt
   # bootroot-agent.key
   ```

### Local Development (Binary)

You can run the agent directly on your host machine.

1. **Start the CA only**

   ```bash
   docker compose up -d step-ca
   ```

   This starts the local PostgreSQL backend automatically via `depends_on`.

2. **Initialize step-ca (first-time)**

   If you are not using the pre-generated test secrets, run `step ca init`
   to create CA keys and config. Store the generated files under `secrets/`
   and update `secrets/config/ca.json` accordingly. (Detailed operator
   docs will be provided separately.)

### Production Notes

- Do not commit production DB credentials. Use secret/env injection.
- Provide a production `secrets/config/ca.json` with the real DSN and
  `db.type` set to `postgresql`.
- Use `sslmode=require` or `verify-full` with proper CA certificates.
- Use a dedicated DB user with least-privilege access to the step-ca schema.
- Rotate DB credentials by updating the injected secret and regenerating
  `secrets/config/ca.json`.
- Restrict network access so only step-ca can reach the PostgreSQL service.
- Back up the PostgreSQL database and test restores regularly.

1. **Run the Agent**

   ```bash
   cp agent.toml.example agent.toml
   # Edit agent.toml to match your daemon profiles and paths
   cargo run -- --config agent.toml
   ```

   *(Note: You might need to handle TLS trust for `try-ca` manually or ignore
   cert errors if supported by flags)*

### Daemon Mode (Auto-Renewal)

By default, the agent runs as a long-lived process. To run once and exit:

```bash
cargo run -- --oneshot
```

Example with custom paths and CA URL:

```bash
cargo run -- \
  --oneshot \
  --ca-url https://localhost:9000/acme/acme/directory
```

Configure the renewal cadence in `agent.toml`:

```toml
domain = "trusted.domain"

[[profiles]]
daemon_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.daemon]
check_interval = "1h"
renew_before = "720h"
check_jitter = "0s"
```

### Environment Overrides

Environment variables override global `agent.toml` settings, and CLI flags
override environment variables. Profile definitions should live in
`agent.toml`.

Nested keys use double underscores. Examples:

```bash
export BOOTROOT_EMAIL="ops@example.com"
export BOOTROOT_DOMAIN="trusted.domain"
export BOOTROOT_SCHEDULER__MAX_CONCURRENT_ISSUANCES="3"
export BOOTROOT_RETRY__BACKOFF_SECS="5,10,30"
```

### Post-Renewal Hooks

You can run commands after a renewal succeeds or fails:

```toml
[profiles.hooks.post_renew]
success = [
  {
    command = "nginx"
    args = ["-s", "reload"]
    timeout_secs = 30
    on_failure = "continue"
  }
]
failure = [
  {
    command = "logger"
    args = ["bootroot renewal failed"]
    timeout_secs = 30
  }
]
```

Hook environment variables include:
`CERT_PATH`, `KEY_PATH`, `DOMAINS`, `PRIMARY_DOMAIN`, `RENEWED_AT`,
`RENEW_STATUS`, `RENEW_ERROR`, `ACME_SERVER_URL`.

Hook behavior notes:

- `timeout_secs` defaults to 30 seconds.
- `retry_backoff_secs` is optional; when set, hooks retry with the given delays.
- `working_dir` is optional; when set, hooks run from that directory.
- `max_output_bytes` caps stdout/stderr and logs when truncation happens.
- `on_failure` controls whether failures stop or continue the hook chain.

### Configuration Schema

Defaults (if not provided):

- `server`: `https://localhost:9000/acme/acme/directory`
- `email`: `admin@example.com`
- `domain`: `trusted.domain`
- `acme.directory_fetch_attempts`: `10`
- `acme.directory_fetch_base_delay_secs`: `1`
- `acme.directory_fetch_max_delay_secs`: `10`
- `acme.poll_attempts`: `15`
- `acme.poll_interval_secs`: `2`
- `acme.http_responder_url`: `http://localhost:8080`
- `acme.http_responder_hmac`: (required)
- `acme.http_responder_timeout_secs`: `5`
- `acme.http_responder_token_ttl_secs`: `300`

Responder flow notes:

- `acme.http_responder_url` points to the responder **admin API** that
  bootroot-agent calls to register tokens.
- The responder listens on port 80 for step-ca’s HTTP-01 requests and replies
  to `/.well-known/acme-challenge/<token>` with the key authorization.
- ACME issuance accepts only DNS/IP identifiers; URI SANs are ignored.
- DNS SAN is auto-generated as
  `instance_id.daemon_name.hostname.domain` and must resolve (from step-ca) to
  the HTTP-01 responder IP.
- `retry.backoff_secs`: `[5, 10, 30]`
- `scheduler.max_concurrent_issuances`: `3`
- `profiles[].daemon.check_interval`: `1h`
- `profiles[].daemon.renew_before`: `720h`
- `profiles[].daemon.check_jitter`: `0s`
- `profiles[].retry.backoff_secs`: `retry.backoff_secs` (fallback)
- `profiles[].hooks.post_renew.*.timeout_secs`: `30`
- `profiles[].hooks.post_renew.*.on_failure`: `continue`

Validation rules:

- `acme.directory_fetch_attempts` > 0
- `acme.directory_fetch_base_delay_secs` > 0
- `acme.directory_fetch_max_delay_secs` > 0 and >= base delay
- `acme.poll_attempts` > 0
- `acme.poll_interval_secs` > 0
- `acme.http_responder_url` is non-empty
- `acme.http_responder_hmac` is non-empty
- `acme.http_responder_timeout_secs` > 0
- `acme.http_responder_token_ttl_secs` > 0
- `retry.backoff_secs` is non-empty and all values > 0
- `scheduler.max_concurrent_issuances` > 0
- `profiles` is non-empty
- `domain` is non-empty ASCII
- `profiles[].daemon_name`, `profiles[].hostname` are non-empty
- `profiles[].instance_id` is numeric
- `profiles[].paths.cert` and `profiles[].paths.key` are non-empty
- `profiles[].retry.backoff_secs` values > 0 (when set)
- `profiles[].hooks.post_renew.*.command` is non-empty
- `profiles[].hooks.post_renew.*.working_dir` is non-empty (when set)
- `profiles[].hooks.post_renew.*.timeout_secs` > 0
- `profiles[].hooks.post_renew.*.retry_backoff_secs` values > 0
- `profiles[].hooks.post_renew.*.max_output_bytes` > 0 (when set)

### Operational Guide

- Renewal is triggered per profile when the cert is missing or expires within
  `profiles[].daemon.renew_before`.
- Daemon checks run per profile with `profiles[].daemon.check_interval`, with
  optional `profiles[].daemon.check_jitter` to avoid synchronized polling
  (minimum 1s delay).
- Issuance retries use `retry.backoff_secs` delays; the last error is logged.
- Hook failures respect `on_failure` (`continue` or `stop`), with optional
  `retry_backoff_secs` and `timeout_secs`.
- Override order is `agent.toml` < ENV < CLI.

## Directory Structure

- `src/`: Rust source code (ACME client implementation).
- `secrets/`: Test CA credentials and configuration.
- `certs/`: Output directory for issued certificates.
- `docker-compose.yml`: Integration test setup (`step-ca` + `agent`).
- `Dockerfile`: Production build definition for the agent.

## Quality Gates

All contributions must pass the following checks:

```bash
# Format
cargo fmt -- --check --config group_imports=StdExternalCrate

# Lint
cargo clippy --all-targets -- -D warnings
biome ci --error-on-warnings .

# Test
cargo test
```
