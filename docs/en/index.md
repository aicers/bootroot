# Bootroot Manual

This manual explains how to install, configure, and operate **bootroot-agent**
with **step-ca**. It is written so that a reader with no PKI background can
complete a full installation and issue certificates successfully.

## CLI Map (Skeleton)

The CLI sections are placeholders for future updates. The manual content
below remains the authoritative reference until the CLI is fully documented.

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot app add`
- `bootroot app info`
- `bootroot verify`

### bootroot infra up

TBD (CLI documentation will be added as implementation lands).

#### Inputs

TBD

#### Outputs

TBD

#### Failures

TBD

#### Examples

TBD

### bootroot init

TBD (CLI documentation will be added as implementation lands).

#### Inputs

TBD

#### Outputs

TBD

#### Failures

TBD

#### Examples

TBD

### bootroot status

TBD (CLI documentation will be added as implementation lands).

#### Inputs

TBD

#### Outputs

TBD

#### Failures

TBD

#### Examples

TBD

### bootroot app add

TBD (CLI documentation will be added as implementation lands).

#### Inputs

TBD

#### Outputs

TBD

#### Failures

TBD

#### Examples

TBD

### bootroot app info

TBD (CLI documentation will be added as implementation lands).

#### Inputs

TBD

#### Outputs

TBD

#### Failures

TBD

#### Examples

TBD

### bootroot verify

TBD (CLI documentation will be added as implementation lands).

#### Inputs

TBD

#### Outputs

TBD

#### Failures

TBD

#### Examples

TBD

## What Bootroot Does

Bootroot is a product-embedded PKI bootstrap layer. A bootstrap prepares the
initial environment so a system can start securely from day one. CA is short
for **Certificate Authority**, the service that signs certificates to assert
identity. ACME (Automated Certificate Management Environment) is the RFC 8555
protocol used for automated issuance. step-ca is an open-source project.

Components:

- **step-ca**: A private ACME-compatible CA
- **PostgreSQL**: The database server used by step-ca
- **bootroot-agent**: A Rust ACME client developed in this project
- **HTTP-01 responder**: A dedicated daemon that answers HTTP-01 challenges

## Manual Map

- **Concepts**: PKI, ACME, CSR, SAN, and mTLS basics
- **Getting Started**: Quick Docker-based issuance flow
- **Installation**: step-ca + PostgreSQL + bootroot-agent + responder setup
- **Configuration**: `agent.toml`, profiles, hooks, retries, and EAB
- **Operations**: Renewal, logs, backup, and security
- **Troubleshooting / FAQ**: Common issues and answers

## Architecture (High Level)

1. bootroot-agent fetches the ACME directory from step-ca
2. It registers an ACME account (optionally with EAB)
3. It requests an order for a domain/SAN set
4. It registers HTTP-01 tokens with the responder
5. The responder serves HTTP-01 on port 80
6. It finalizes the order and writes cert/key to disk
7. It runs hooks and schedules renewals (daemon mode)

## Key Files in This Repo

- `agent.toml.example`: Full multi-profile configuration example
- `agent.toml.compose`: Example used by Docker Compose
- `secrets/config/ca.json`: step-ca configuration (dev)
- `scripts/update-ca-db-dsn.sh`: Update `ca.json` DB DSN from env
- `docs/en/*` and `docs/ko/*`: Manual source

## Safety Notes

- Do not commit production secrets to git.
- Private keys should be `0600` and secret directories `0700`.
- Use restricted network access between CA and PostgreSQL.
