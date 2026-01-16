# Bootroot Manual

This manual explains how to install, configure, and operate **bootroot**
(bootroot CLI, bootroot-agent, and the HTTP-01 responder) with **step-ca**
and **OpenBao**. It is written so that a reader with no PKI background can
complete a full installation and issue certificates successfully. The
bootroot CLI binary is `bootroot`, and the bootroot-agent binary is
`bootroot-agent`.

## CLI

CLI usage is documented in the [CLI manual](cli.md). The rest of this manual focuses
on the **manual setup** flow.

## What Bootroot Does

Bootroot is a product-embedded PKI bootstrap layer. A bootstrap prepares the
initial environment so a system can start securely from day one. CA is short
for **Certificate Authority**, the service that signs certificates to assert
identity. ACME (Automated Certificate Management Environment) is the RFC 8555
protocol used for automated issuance.

Components:

- **step-ca**: A private ACME-compatible CA (open source)
- **PostgreSQL**: The database server used by step-ca (open source)
- **OpenBao**: Secrets manager for bootroot inputs and rotation (open source)
- **bootroot-agent**: A Rust ACME client developed in this project
- **HTTP-01 responder**: An HTTP-01 daemon developed in this project

## Manual Map

- **CLI**: infra bring-up, initialization, status, app onboarding,
  verification, and rotation
- **Concepts**: PKI, ACME, CSR, SAN, mTLS, and OpenBao basics
- **Getting Started**: Quick Docker-based issuance flow
- **Installation**: OpenBao + step-ca + PostgreSQL + bootroot-agent +
  responder setup
- **Configuration**: `agent.toml`, profiles, hooks, retries, and EAB
- **Operations**: Renewal, logs, backup, and security (including OpenBao)
- **Troubleshooting / FAQ**: Common issues and answers

## Architecture (High Level)

1. bootroot-agent fetches the ACME directory from step-ca
2. It registers an ACME account (optionally with EAB)
3. It requests an order for a domain/SAN set
4. It registers HTTP-01 tokens with the responder
5. The responder serves HTTP-01 on port 80
6. It finalizes the order and writes cert/key to disk
7. It runs hooks and schedules renewals (daemon mode)
8. OpenBao supplies secrets to bootroot components via rendered files

## Key Files in This Repo

- `agent.toml.example`: Full multi-profile configuration example
- `agent.toml.compose`: Example used by Docker Compose
- `secrets/config/ca.json`: step-ca configuration (dev)
- `openbao-agent/*.hcl`: OpenBao Agent templates (render secrets to files)
- `scripts/update-ca-db-dsn.sh`: Update `ca.json` DB DSN from env
- `docs/en/*` and `docs/ko/*`: Manual source

## Safety Notes

- Do not commit production secrets to git.
- Private keys should be `0600` and secret directories `0700`.
- Store OpenBao tokens/unseal keys in secure storage.
- Use restricted network access between CA and PostgreSQL.
