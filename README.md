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
   # Make sure you have the root CA trusted or use valid certs
   # For dev, we point to the local ACME directory
   cargo run -- \
     --ca-url https://localhost:9000/acme/acme/directory \
     --domain my-local-service.com \
     --cert-path ./certs/my-cert.crt \
     --key-path ./certs/my-key.key
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
  --ca-url https://localhost:9000/acme/acme/directory \
  --domain my-local-service.com \
  --cert-path ./certs/my-cert.crt \
  --key-path ./certs/my-key.key
```

Configure the renewal cadence in `agent.toml`:

```toml
[daemon]
check_interval = "1h"
renew_before = "720h"
check_jitter = "0s"
```

### Environment Overrides

Environment variables override `agent.toml`, and CLI flags override
environment variables.

Nested keys use double underscores. Examples:

```bash
export BOOTROOT_EMAIL="ops@example.com"
export BOOTROOT_PATHS__CERT="/etc/bootroot/cert.pem"
export BOOTROOT_DAEMON__RENEW_BEFORE="720h"
export BOOTROOT_DAEMON__CHECK_JITTER="0s"
export BOOTROOT_DOMAINS="example.com,api.example.com"
export BOOTROOT_RETRY__BACKOFF_SECS="5,10,30"
```

### Post-Renewal Hooks

You can run commands after a renewal succeeds or fails:

```toml
[hooks.post_renew]
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

### Operational Guide

- Renewal is triggered when the cert is missing or expires within
  `daemon.renew_before`.
- Daemon checks run every `daemon.check_interval`, with optional
  `daemon.check_jitter` to avoid synchronized polling.
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
