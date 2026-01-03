# bootroot

**bootroot** is a product-embedded PKI bootstrap and trust foundation. It packages `step-ca` to provide an automated, ACME-based private Certificate Authority for your infrastructure.

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Quick Start

1. **Initialize the CA** (First time only)

   This script generates the Root CA, Intermediate CA, and basic configuration in the `secrets/` directory.

   ```bash
   go run ./cmd/bootroot
   ```

2. **Start the Service**

   ```bash
   cd deploy
   docker-compose up -d
   ```

3. **Verify**

   Check if the CA is running:
   ```bash
   curl -k https://localhost:9000/health
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

- `deploy/`: Docker Compose files
- `scripts/`: Initialization and utility scripts
- `config/`: Application configurations
- `secrets/`: Generated CA keys, certs, and password files (Git-ignored)

## Documentation

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed architectural contract.
