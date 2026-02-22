# Operations

This section focuses on operational checks and incident response procedures.
See **Installation** and **Configuration** for full setup steps and options.
For CLI command syntax, see [CLI](cli.md).

For CI/test operations, see [CI & E2E](e2e-ci.md).

## Automation boundary (must read)

Bootroot-managed scope:

- generation and updates of config/material files (`agent.toml`, `agent.hcl`,
  `agent.toml.ctmpl`, `token`, and bootstrap-related files)
- per-delivery-mode state recording and bootstrap input preparation
  during service add
- operational command flow entry points (`rotate`, `verify`, `status`)

Operator-managed scope:

- binary installation/update (`bootroot`, `bootroot-agent`, `bootroot-remote`,
  OpenBao Agent)
- process supervision for always-on behavior (start/restart/boot startup)
- runtime setup (for example, `docker compose` service definitions or
  `systemd` units/timers) and boot-time start/restart policies

Policy summary:

- recommended runtime differs by deployment target:
  step-ca/OpenBao/HTTP-01 responder run as independent services
  (Compose or systemd).
  For services added via `bootroot service add`, Docker services are best
  operated with per-service agent sidecars, while daemon services are best
  operated as host daemons (systemd).
- in all paths, operators must satisfy reliability requirements directly
  (always-on, restart, dependency ordering).
- In both paths, bootroot does not fully manage the entire process lifecycle.

## Core operational checks

Run these regularly for fast health checks:

```bash
bootroot status
bootroot verify --service-name <service> --db-check
bootroot service info --service-name <service>
bootroot monitoring status
```

- `bootroot status`: overall state from OpenBao/step-ca/state file perspective
- `bootroot verify --service-name <service> --db-check`:
  non-interactive issuance/verification/DB/responder checks
- `bootroot service info --service-name <service>`:
  current per-service state including delivery mode
- `bootroot monitoring status`: Prometheus/Grafana container status

## bootroot-agent

- Monitor logs for issuance, authorization, and hook results.
- Ensure key/secret permissions stay `0600`/`0700` on disk.
- Use hooks to reload dependent services after renewals
  (hook definitions live in **Configuration**).
- Services that use mTLS must be able to read the CA bundle
  (for example, `trust.ca_bundle_path`).

## step-ca + PostgreSQL

- Back up the PostgreSQL database regularly.
- Test restores in a staging environment.
- Store backups in a secure location with restricted access.

## HTTP-01 responder

- Ensure port 80 is reachable from step-ca to the responder.
- Ensure the admin API (default 8080) is reachable from bootroot-agent.
- Keep `acme.http_responder_hmac` consistent with the responder secret.
- If binding to port 80 under systemd, run as root or grant
  `cap_net_bind_service`.

## OpenBao

- Regularly check OpenBao seal status.
- Store unseal keys and the root token securely and separately.
- Keep AppRole/policies scoped to the minimum required paths.
- Include KV v2 data in backup/snapshot policies.
- Confirm reload/restart behavior for bootroot-agent/step-ca after rotations.

## Monitoring operations

- Use `bootroot monitoring up --profile lan|public` to start monitoring.
- `bootroot monitoring status` prints running profile status plus
  Grafana URL/admin-password status.
- Use `bootroot monitoring down` to stop/remove monitoring containers.
- To reset Grafana admin password to the initial state, run
  `bootroot monitoring down --reset-grafana-admin-password`.

## Compose operations procedure (recommended)

- Keep workload containers and required sidecars/agents running continuously.
- Set explicit restart policy (`restart: always` or `restart: unless-stopped`).
- Ensure Docker/Compose itself is managed by systemd (or equivalent) so
  services recover after host reboot.
- Basic triage flow:
  `docker compose ps` -> `docker compose logs --tail=200 <service>`
  -> `bootroot verify --service-name <service>`.

## systemd operations procedure (supported)

- Register `bootroot-agent` as a long-running service with
  `Restart=on-failure` and `WantedBy=multi-user.target`.
- If OpenBao Agent is systemd-managed, split it per service and define
  dependency ordering such as `After=network-online.target`.
- Run `bootroot-remote bootstrap` once per service at initial setup, then use
  `bootroot-remote apply-secret-id` after secret_id rotation.
- Triage flow:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --service-name <service>`.

## Rotation scheduling

Run `bootroot rotate ...` on a schedule (cron/systemd timer). Keep secrets out
of command history; use environment files or secure stores.
For day-2 automation, use runtime AppRole auth (`--auth-mode approle`) instead
of root token. Root token should be kept for bootstrap/break-glass only.
`bootroot` does not include a built-in persistent root-token store.

Example (cron):

```cron
0 3 * * 0 OPENBAO_APPROLE_ROLE_ID=... OPENBAO_APPROLE_SECRET_ID=... \
  bootroot rotate --auth-mode approle stepca-password --yes
```

Example (systemd timer):

```ini
[Unit]
Description=Rotate step-ca password weekly

[Service]
Type=oneshot
EnvironmentFile=/etc/bootroot/rotate.env
ExecStart=/usr/local/bin/bootroot rotate stepca-password --yes
```

```ini
[Unit]
Description=Weekly step-ca password rotation

[Timer]
OnCalendar=Sun 03:00
Persistent=true

[Install]
WantedBy=timers.target
```

## Remote bootstrap and secret_id handoff operations

For targets added with `--delivery-mode remote-bootstrap`, the operational
model is one-shot bootstrap followed by explicit secret_id handoff:

1. Run `bootroot-remote bootstrap` once on the service machine after
   `bootroot service add` to apply the initial configuration bundle.
2. After `bootroot rotate approle-secret-id` on the control node, run
   `bootroot-remote apply-secret-id` on the service machine to deliver the
   new secret_id.

Minimum environment/config checklist:

- OpenBao endpoint and KV mount
- service name and AppRole file paths (`role_id`, `secret_id`)
- EAB file path and `agent.toml` path
- profile identity/path fields (hostname, instance_id, cert/key paths)
- CA bundle path when trust data includes `ca_bundle_pem`

Security notes:

- secret directories `0700`, secret files `0600`
- limit service account access to service-specific paths only
- treat `bootroot init --summary-json` output as sensitive because it may
  include `root_token`

## OpenBao restart/recovery checklist

- If OpenBao is `sealed`, unseal it first with unseal keys.
- After unseal, provide runtime auth for operational commands:
  - day-2 `service add`/`rotate`: prefer AppRole (`--auth-mode approle`)
  - bootstrap/break-glass admin tasks: root token (`--auth-mode root`)
- Keep unseal and runtime-auth steps separate in runbooks: unseal completion
  does not satisfy OpenBao auth requirements by itself.

## CA bundle (trust) operations

This section covers how to operate three trust settings together:
`trust.ca_bundle_path`, `trust.trusted_ca_sha256`, and
`trust.verify_certificates`.

- When `trust.ca_bundle_path` and `trust.trusted_ca_sha256` are configured,
  bootroot-agent splits the ACME issuance response into leaf + chain.
  The leaf cert/key are stored in service paths, and the chain
  (intermediate/root) is written to `trust.ca_bundle_path`.
- If `trust.trusted_ca_sha256` is set, bundle write is allowed only when the
  chain fingerprint check passes. A mismatch fails issuance.
- If the response has no chain, the CA bundle is not updated and a warning
  is logged.
- With `trust.verify_certificates = true`, bootroot-agent verifies the ACME
  server (step-ca) TLS certificate. If `ca_bundle_path` is set, it uses that
  bundle; otherwise it uses the system CA store.
- CLI overrides:
  `bootroot-agent --verify-certificates` (force verify for that run) or
  `bootroot-agent --insecure` (disable verify only for that run).
- In normal mode (without `--insecure`), after the first successful issuance,
  bootroot-agent auto-writes `trust.verify_certificates = true` in
  `agent.toml`, so subsequent runs switch to verification mode.
- If file write or reload validation fails during this hardening step,
  bootroot-agent exits non-zero.

Permissions/ownership:

- The **service consuming** the CA bundle must be able to read the file.
- The simplest setup is running bootroot-agent and the service as the **same
  user or group**.

## Trust rotation

After renewing or replacing CA certificates, run `bootroot rotate trust-sync`
to propagate the updated fingerprints and bundle PEM:

```bash
bootroot rotate trust-sync --yes
```

This command:

1. Computes SHA-256 fingerprints for root and intermediate CA certs under
   `secrets/certs/`.
2. Writes the fingerprints and concatenated PEM bundle to OpenBao
   (`bootroot/ca`).
3. For each remote service, writes the trust payload to
   `bootroot/services/<name>/trust`.
4. For each local service, updates the `[trust]` section in the agent config
   and writes `ca-bundle.pem` to disk.

## Force reissue

To delete a service's certificate and key and trigger bootroot-agent to
reissue:

```bash
bootroot rotate force-reissue --service-name edge-proxy --yes
```

For local services (daemon/docker), the command signals bootroot-agent after
deleting the files. For remote services, it prints a hint to run
`bootroot-remote bootstrap` on the service host.
