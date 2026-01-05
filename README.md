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

## Getting Started

### Prerequisites

- **Rust** (latest stable)
- **Docker** & **Docker Compose**
- **Biome** (`brew install biome`) for development.

### Quick Start (Docker)

This is the easiest way to verify the agent and CA integration.

1. **Start Services**

   The repository comes with pre-generated test secrets in `secrets/`.

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

2. **Run the Agent**

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
[[profiles]]
name = "edge-proxy-a"
uri_san_enabled = true

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
export BOOTROOT_SPIFFE_TRUST_DOMAIN="trusted.domain"
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
- `on_failure` controls whether failures stop or continue the hook chain.

### Configuration Schema

Defaults (if not provided):

- `server`: `https://localhost:9000/acme/acme/directory`
- `email`: `admin@example.com`
- `spiffe_trust_domain`: `trusted.domain`
- `acme.http_challenge_port`: `80`
- `acme.directory_fetch_attempts`: `10`
- `acme.directory_fetch_base_delay_secs`: `1`
- `acme.directory_fetch_max_delay_secs`: `10`
- `acme.poll_attempts`: `15`
- `acme.poll_interval_secs`: `2`
- `retry.backoff_secs`: `[5, 10, 30]`
- `scheduler.max_concurrent_issuances`: `3`
- `profiles[].daemon.check_interval`: `1h`
- `profiles[].daemon.renew_before`: `720h`
- `profiles[].daemon.check_jitter`: `0s`
- `profiles[].uri_san_enabled`: `true`
- `profiles[].hooks.post_renew.*.timeout_secs`: `30`
- `profiles[].hooks.post_renew.*.on_failure`: `continue`

Validation rules:

- `spiffe_trust_domain` is non-empty ASCII
- `acme.directory_fetch_attempts` > 0
- `acme.directory_fetch_base_delay_secs` > 0
- `acme.directory_fetch_max_delay_secs` > 0 and >= base delay
- `acme.poll_attempts` > 0
- `acme.poll_interval_secs` > 0
- `retry.backoff_secs` is non-empty and all values > 0
- `scheduler.max_concurrent_issuances` > 0
- `profiles` is non-empty
- `profiles[].name`, `profiles[].daemon_name`, `profiles[].hostname` are non-empty
- `profiles[].instance_id` is numeric
- `profiles[].domains` is non-empty
- `profiles[].paths.cert` and `profiles[].paths.key` are non-empty
- `profiles[].hooks.post_renew.*.command` is non-empty
- `profiles[].hooks.post_renew.*.timeout_secs` > 0
- `profiles[].hooks.post_renew.*.retry_backoff_secs` values > 0

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
