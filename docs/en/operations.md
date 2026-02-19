# Operations

This section focuses on operational checks and incident response procedures.
See **Installation** and **Configuration** for full setup steps and options.
For CLI command syntax, see [CLI](cli.md).

For CI/test operations, see [CI & E2E](e2e-ci.md).

## Automation boundary (must read)

Bootroot-managed scope:

- generation and updates of config/material files (`agent.toml`, `agent.hcl`,
  `agent.toml.ctmpl`, `token`, and sync-related files)
- per-delivery-mode state recording and sync input preparation during service add
- operational command flow entry points (`rotate`, `verify`, `status`)

Operator-managed scope:

- binary installation/update (`bootroot`, `bootroot-agent`, `bootroot-remote`,
  OpenBao Agent)
- process supervision for always-on behavior (start/restart/boot startup)
- runtime integration (`docker compose` or `systemd`)

Policy summary:

- Compose is the recommended runtime path.
- systemd is supported, but operators must satisfy the same reliability
  requirements directly (always-on, restart, dependency ordering).
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
  current per-service state including delivery mode and per-item sync-status
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
- Run `bootroot-remote` periodically per service (timer/cron) and apply overlap
  prevention lock (`flock`).
- Triage flow:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --service-name <service>`.

## Rotation scheduling

Run `bootroot rotate ...` on a schedule (cron/systemd timer). Keep secrets out
of command history; use environment files or secure stores.
`bootroot rotate` commands require an OpenBao root token. Provide it via
`--root-token` or `OPENBAO_ROOT_TOKEN` (otherwise you will be prompted).

Example (cron):

```cron
0 3 * * 0 OPENBAO_ROOT_TOKEN=... bootroot rotate stepca-password --yes
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

## Remote sync periodic operations

For targets added with `--delivery-mode remote-bootstrap`, run a periodic
`bootroot-remote sync` job.
Template files are provided:

- `scripts/bootroot-remote-sync.service`
- `scripts/bootroot-remote-sync.timer`
- `scripts/bootroot-remote-sync.cron`

Recommended pattern:

- one periodic sync job per service
- one `--summary-json` file per service
- keep role/secret/token/config paths service-scoped
- apply overlap prevention lock (`flock` or equivalent)

Minimum environment/config checklist:

- OpenBao endpoint and KV mount
- service name and AppRole file paths (`role_id`, `secret_id`)
- EAB file path and `agent.toml` path
- profile identity/path fields (hostname, instance_id, cert/key paths)
- CA bundle path when trust sync is enabled

Failure handling guidance:

- use retry/backoff/jitter controls in `bootroot-remote sync`
- alert on repeated `failed`/`expired` sync-status values
- inspect pull summary JSON + `bootroot service sync-status` output together

systemd timer example (overlap prevention):

```ini
[Service]
Type=oneshot
ExecStart=/usr/bin/flock -n /var/lock/bootroot-remote-<service>.lock \
  /usr/local/bin/bootroot-remote sync ...
```

Manual ingest (exception path):

- Use the command below only when you need to ingest a previously generated
  summary JSON manually.

```bash
bootroot service sync-status \
  --service-name <service> \
  --summary-json <service>-remote-summary.json
```

Security notes:

- secret directories `0700`, secret files `0600`
- summary JSON is primarily status/error metadata; still keep it out of broad
  shared logs and apply retention controls
- limit service account access to service-specific paths only

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
