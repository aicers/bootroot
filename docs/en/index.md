# Bootroot Manual

This manual explains how to install, configure, and operate **bootroot**
(bootroot CLI, bootroot-agent, and the HTTP-01 responder) with **step-ca**,
**OpenBao**, **Prometheus**, and **Grafana**. It is written so that a reader
with no PKI background can
complete a full installation and issue certificates successfully. The
bootroot CLI binary is `bootroot`, and the bootroot-agent binary is
`bootroot-agent`.

## What Bootroot Does

Bootroot is a product-embedded PKI bootstrap layer. A bootstrap prepares the
initial environment so a system can start securely from day one. CA is short
for **Certificate Authority**, the service that signs certificates to assert
identity. ACME (Automated Certificate Management Environment) is the RFC 8555
protocol used for automated issuance.
In this manual, a service means a user application (daemon/docker deployment
target) that requires certificates for service-to-service mTLS communication.
Bootroot's role is to **automatically issue, renew, and rotate certificates**
so those services can communicate over mTLS. It also
uses Prometheus and Grafana to collect and visualize metrics for operations.

Components:

- **step-ca**: A private ACME-compatible CA (open source)
- **PostgreSQL**: The database server used by step-ca (open source)
- **OpenBao**: Secrets manager for bootroot inputs and rotation (open source)
- **OpenBao Agent**: Agent that renders OpenBao secrets to files (open source)
- **bootroot CLI**: A CLI tool developed in this project that automates
  install, init, and operations
- **bootroot-agent**: A Rust ACME client developed in this project
- **HTTP-01 responder**: An HTTP-01 daemon developed in this project
- **Prometheus**: Metrics collector (open source)
- **Grafana**: Metrics visualization dashboards (open source)

CA is short for **Certificate Authority**, the service that signs certificates
to assert identity. ACME (Automated Certificate Management Environment) is the
RFC 8555 protocol used for automated issuance.

## Manual Map

- **CLI**: infra bring-up/initialization/status plus service onboarding,
  issuance verification, secret rotation, and monitoring guidance
- **Concepts**: PKI, ACME, CSR, SAN, mTLS, and OpenBao basics
- **Getting Started**: Quick Docker-based issuance flow
- **Installation**: OpenBao + step-ca + PostgreSQL + bootroot-agent +
  responder setup
- **Configuration**: `agent.toml`, profiles, hooks, retries, and EAB
- **Operations**: Renewal, logs, backup, and security (including OpenBao)
- **Troubleshooting / FAQ**: Common issues and answers

CLI usage is documented in the [CLI manual](cli.md) and the
[CLI examples](cli-examples.md). The CLI manual covers
core commands like `infra up/init/status`, `service add/verify`, `rotate`, and
`monitoring`.
The rest of this manual focuses on the **manual setup** flow.

## Installation Topology (Summary)

The `bootroot` CLI assumes a topology where `step-ca (with PostgreSQL)`,
`OpenBao`, and the `HTTP-01 responder` are installed on the **same machine**.
This is the most natural default path for security (simpler trust boundary),
convenience (more automation), and operations (simpler troubleshooting and
runbooks).
`Prometheus` and `Grafana` are also typically colocated on that machine to
monitor `OpenBao` and `step-ca`.

With this assumption, dedicated OpenBao Agents for `step-ca` and `responder`
must also run on that same machine as dedicated instances for each of them.

A distributed layout (for example, running `step-ca`, `OpenBao`, and responder
on different machines) is theoretically possible, but it requires manual
installation/configuration instead of the `bootroot` CLI automation path.
Also, we cannot guarantee that the current `bootroot` setup fully supports
every such topology.

During service onboarding, `bootroot service add` prints deployment-type
(`daemon`/`docker`) specific run guidance and snippets.

OpenBao Agent placement rules:

- Docker service: per-service **OpenBao Agent sidecar** is **required**
- daemon service: per-service **OpenBao Agent daemon** is **required**

bootroot-agent placement rules:

- Docker service: per-service **bootroot-agent sidecar** is recommended
- daemon service: one shared **bootroot-agent daemon** per host is recommended

Note: Docker services can use the shared daemon, but this is not recommended
for isolation, lifecycle alignment, and failure blast-radius reasons.

## Architecture (High Level)

1. OpenBao supplies secrets to bootroot components via rendered files
2. bootroot-agent fetches the ACME directory from step-ca
3. It registers an ACME account (optionally with EAB)
4. It requests an order for a domain/SAN set
5. It registers HTTP-01 tokens with the responder
6. The responder serves HTTP-01 on port 80
7. It finalizes the order and writes cert/key to disk
8. It runs hooks and schedules renewals (daemon mode)

## Safety Notes

- Do not commit production secrets to git.
- Secret files must be `0600`, and secret directories must be `0700`.
- Store OpenBao tokens/unseal keys in secure storage.
- Follow the default Bootroot setup: install CA and DB on the same machine,
  and do not expose the DB externally.
