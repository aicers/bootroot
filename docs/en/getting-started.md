# Getting Started

This section walks through a full end-to-end issuance using Docker Compose.
If you are using the CLI, see `docs/en/cli.md`. This document focuses on the
**manual** flow.

## Prerequisites

- Docker and Docker Compose
- Port 80 accessible to the HTTP-01 responder inside the compose network
- The auto-generated DNS SAN must resolve **from step-ca to the HTTP-01 responder**
  - In Compose, `docker-compose.yml` gives `bootroot-http01` the
    `001.bootroot-agent.bootroot-agent.trusted.domain` network alias
  - If you change `domain`, update the alias or map it in step-ca `/etc/hosts`
  - Auto-generated scheme:
    `<instance-id>.<daemon-name>.<hostname>.<domain>`

## Quick Start (Compose)

1. Start the stack:

   ```bash
   docker compose up --build -d
   ```

2. Watch the agent logs until issuance succeeds:

   ```bash
   docker logs -f bootroot-agent
   ```

   Expected log: `Successfully issued certificate!`

3. Confirm output files:

   ```bash
   ls -l certs/
   ```

   Expected files: `bootroot-agent.crt`, `bootroot-agent.key`

## What Just Happened

- The agent read `agent.toml.compose`
- It registered an ACME account on step-ca
- It registered HTTP-01 tokens with the responder
- The responder served HTTP-01 on port 80 and the agent wrote cert/key to `certs/`

## Next Steps

- Read **Installation** for production setups
- Read **Configuration** to add more profiles and hooks
- For production, inject step-ca passwords/DSN/HMAC/EAB via OpenBao
