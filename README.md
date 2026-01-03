# bootroot

[![CI](https://github.com/aicers/bootroot/actions/workflows/ci.yml/badge.svg)](https://github.com/aicers/bootroot/actions/workflows/ci.yml)

**bootroot** is a product-embedded PKI bootstrap and trust foundation.
It packages `step-ca` to provide an automated, ACME-based private Certificate
Authority for your infrastructure.

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Quick Start

1. **Initialize the CA** (First time only)

   This script generates the Root CA, Intermediate CA, and basic configuration
   in the `secrets/` directory.

   ```bash
   go run ./cmd/bootroot
   ```

2. **Start Services**

   This starts both the CA (`bootroot-ca`) and the ACME Agent (`bootroot-agent`).

   ```bash
   cd deploy
   docker-compose up -d
   ```

3. **Verify**

   Check if the CA is running:

   ```bash
   curl -k https://localhost:9000/health
   ```

   Check if the Agent successfully obtained a certificate:

   ```bash
   docker logs bootroot-agent 2>&1 | grep "Successfully issued certificate"
   ```

### Cleanup

To stop the services and remove all generated secrets (reset to clean state):

```bash
# Stop containers
cd deploy
docker-compose down

# Remove secrets
cd ..
rm -rf secrets/
```

## Directory Structure

- `deploy/`: Docker Compose and Dockerfile for Agent
- `cmd/bootroot/`: CA Initialization tool
- `cmd/agent/`: Universal ACME Agent
- `scripts/`: Initialization and utility scripts
- `config/`: Application configurations
- `secrets/`: Generated CA keys, certs, and password files (Git-ignored)

## Documentation

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed architectural contract.
