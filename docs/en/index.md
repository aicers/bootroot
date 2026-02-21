# Bootroot Manual

This manual explains how to install, configure, and operate **bootroot**
(bootroot CLI, bootroot-agent, bootroot-remote, and the HTTP-01 responder)
with **step-ca**, **OpenBao**, **Prometheus**, and **Grafana**. It is written
so that a reader with no PKI background can complete a full installation and
issue certificates successfully. The bootroot CLI binary is `bootroot`, the
bootroot-agent binary is `bootroot-agent`, and the remote-service
configuration CLI binary is `bootroot-remote`.

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
- **bootroot-agent**: A Rust ACME client daemon developed in this project
- **bootroot-remote**: A bootstrap CLI tool developed in this
  project for configuring remote services
- **HTTP-01 responder**: An HTTP-01 daemon developed in this project
- **Prometheus**: Metrics collector (open source)
- **Grafana**: Metrics visualization dashboards (open source)

CA is short for **Certificate Authority**, the service that signs certificates
to assert identity. ACME (Automated Certificate Management Environment) is the
RFC 8555 protocol used for automated issuance.

## Manual Map

- **Concepts**: PKI, ACME, CSR, SAN, mTLS, and OpenBao basics
- **CLI**: infra bring-up/initialization/status plus service onboarding,
  issuance verification, secret rotation, monitoring, and remote sync guidance
- **CLI Examples**: scenario-oriented command examples and option patterns
- **Installation**: OpenBao + step-ca + PostgreSQL + bootroot-agent +
  bootroot-remote + responder setup
- **Configuration**: `agent.toml`, profiles, hooks, retries, and EAB
- **Operations**: Renewal, logs, backup, and security (including OpenBao)
- **CI & E2E**: PR-critical matrix, extended workflow, artifacts, and local
  reproduction
- **Troubleshooting**: Common issues and recovery steps

CLI usage is documented in the [CLI manual](cli.md) and the
[CLI examples](cli-examples.md). The CLI manual covers
core commands like `infra up/init/status`, `service add/verify`, `rotate`, and
`monitoring`, plus `bootroot-remote bootstrap`/`apply-secret-id`.
In this manual, the **Installation/Configuration** pages focus on a
non-CLI manual flow; other pages keep an operations/concepts/validation focus.

## Automation Boundary (Summary)

- Bootroot-managed: config/material generation and updates, state recording,
  bootstrap input preparation
- Operator-managed: binary installation/update, process always-on ownership,
  runtime setup (for example, Compose service definitions or systemd
  units/timers) and boot-time start/restart policies

Runtime selection guidance:
Operate step-ca/OpenBao/HTTP-01 responder as independent services
(Compose or systemd). For services added via `bootroot service add`,
recommended operation differs by deployment type: Docker services are best run
with per-service agent sidecars, while daemon services are best run as host
daemons (systemd). In all paths, operators must satisfy reliability
requirements directly.

## Installation Topology (Summary)

The `bootroot` CLI assumes a topology where `step-ca (with PostgreSQL)`,
`OpenBao`, and the `HTTP-01 responder` are installed on the **same machine**.
This is the most natural default path for security (simpler trust boundary),
convenience (more automation), and operations (simpler troubleshooting and
operational procedures).
`Prometheus` and `Grafana` are also typically colocated on that machine to
monitor `OpenBao` and `step-ca`.

With this assumption, dedicated OpenBao Agents for `step-ca` and `responder`
must also run on that same machine as dedicated instances for each of them.

A distributed layout that breaks this baseline is theoretically possible, but
it requires manual installation/configuration instead of the `bootroot` CLI
automation path. For example, place `step-ca+PostgreSQL` on a CA machine,
`OpenBao` on a separate secrets machine, and the `HTTP-01 responder` on an
edge service machine. Also, we cannot guarantee that the current `bootroot`
setup fully supports this topology class.

Services added by `bootroot service add` may run either on the same machine as
step-ca or on different machines. Regardless of placement, each service runtime
must include both OpenBao Agent and bootroot-agent.

OpenBao Agent placement rules:

- Docker service: per-service **OpenBao Agent sidecar** is **required**
- daemon service: per-service **OpenBao Agent daemon** is **required**

bootroot-agent placement rules:

- Docker service: per-service **bootroot-agent sidecar** is recommended
- daemon service: one shared **bootroot-agent daemon** per host is recommended

Note: Docker services can use the shared daemon, but this is not recommended
for isolation, lifecycle alignment, and failure blast-radius reasons.

bootroot-remote placement rules:

- Each service should have `bootroot-remote bootstrap` run once during initial
  setup, with `bootroot-remote apply-secret-id` run after secret_id rotation.

Note:
If a service is added on the machine where step-ca is installed,
bootroot-remote is not required.
If a service is added on a different machine, bootroot-remote must be
deployed on that service machine.

## /etc/hosts Mapping

For certificate issuance/renewal to work reliably, name-to-IP mapping
(`/etc/hosts` or DNS) must satisfy both conditions below. DNS also works, but
in practice many deployments configure `/etc/hosts` mappings directly.

1. step-ca -> service FQDN (HTTP-01 target) -> responder IP  
   step-ca must resolve each service validation FQDN
   (`<instance_id>.<service_name>.<hostname>.<domain>`) to the responder IP.
   Configure mappings in the environment where step-ca runs
   (container/host `/etc/hosts`) or in DNS.

2. Remote service machine -> step-ca/responder name -> IP  
   If a service runs on a different machine from step-ca/OpenBao and that
   machine accesses step-ca/responder by name (not direct IP), those names must
   resolve to the correct IPs on that service machine. Example: when using
   `stepca.internal` and `responder.internal`, configure the same mappings in
   that machine's `/etc/hosts` or DNS.
   If the remote service machine accesses step-ca/responder by IP literal,
   this specific hostname mapping is not required.

## Architecture (High Level)

1. Bring up and initialize CA infrastructure
2. Add services and configure per-service OpenBao Agent and bootroot-agent
3. OpenBao Agent supplies secrets to bootroot components via rendered files
4. bootroot-agent fetches the ACME directory from step-ca
5. It registers an ACME account (optionally with EAB)
6. It requests an order for a domain/SAN set
7. It registers HTTP-01 tokens with the responder
8. The responder serves HTTP-01 on port 80
9. It finalizes the order and writes cert/key to disk
10. bootroot-agent runs service hooks
11. Certificates are renewed periodically

## Safety Notes

- Do not commit production secrets to git.
- Secret files must be `0600`, and secret directories must be `0700`.
- Store OpenBao tokens/unseal keys in secure storage.
- Follow the default Bootroot setup: install CA and DB on the same machine,
  and do not expose the DB externally.
