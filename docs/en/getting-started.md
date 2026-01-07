# Getting Started

This section walks through a full end-to-end issuance using Docker Compose.

## Prerequisites

- Docker and Docker Compose
- Port 80 accessible to the HTTP-01 responder inside the compose network
- `profiles[].domains` must resolve **from step-ca to the HTTP-01 responder**
  - In Compose, `docker-compose.yml` gives `bootroot-http01` the
    `bootroot-agent.com` network alias
  - If you change the domain, update the alias or map it in step-ca `/etc/hosts`

## Quick Start (Compose)

1. Start the stack:

   ```bash
   docker compose up --build -d
   ```

2. Watch the agent logs until issuance succeeds:

   ```bash
   docker logs -f bootroot-agent
   # Expected: "Successfully issued certificate!"
   ```

3. Confirm output files:

   ```bash
   ls -l certs/
   # bootroot-agent.crt
   # bootroot-agent.key
   ```

## What Just Happened

- The agent read `agent.toml.compose`
- It registered an ACME account on step-ca
- It registered HTTP-01 tokens with the responder
- The responder served HTTP-01 on port 80 and the agent wrote cert/key to `certs/`

## Next Steps

- Read **Installation** for production setups
- Read **Configuration** to add more profiles and hooks
