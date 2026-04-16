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
  Hooks can be configured at service onboarding time via
  `bootroot service add --reload-style`/`--reload-target` (presets) or
  `--post-renew-command`/`--post-renew-arg` (low-level), which write the
  `[profiles.hooks.post_renew]` entry into the managed `agent.toml` profile.
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

### Audit logging

A file-based audit backend is declared in `openbao/openbao.hcl` and
enabled automatically when the OpenBao container starts. The audit log
captures every OpenBao API request (authentication, secret reads/writes,
policy changes) and is essential for post-incident investigation.

`bootroot init` verifies that the audit backend is active. If no file
audit device is found (e.g. the audit stanza was removed from
`openbao.hcl`, or the `openbao-audit` volume is not mounted), init
fails. Restore the audit configuration and re-run init.

- **Log location (inside container):** `/openbao/audit/audit.log`
- **Host access:** the log is persisted on the `openbao-audit` Docker
  volume. Inspect it with
  `docker compose exec openbao cat /openbao/audit/audit.log`.
- **Rotation:** OpenBao does not rotate the audit log itself. Use an
  external log rotation tool (e.g. `logrotate` on a bind-mount, or a
  sidecar that tails the volume) and send `SIGHUP` to the OpenBao
  process after rotation so it reopens the file handle.
- **Verification:** confirm the audit device is active with
  `docker compose exec openbao bao audit list`.

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

## SecretID TTL and rotation cadence

Service AppRole `secret_id` values are reusable runtime credentials. They
survive normal restarts and re-authentication until the next planned
rotation. The `secret_id_ttl` controls how long a SecretID remains valid
after issuance.

**Default TTL model:**

- `24h` is the role-level default set during `bootroot init`. This is the
  security-conservative choice: a shorter lifetime limits exposure when a
  SecretID leaks.
- `48h` (`RECOMMENDED_SECRET_ID_TTL`) is the CLI warning threshold. Values
  above `48h` emit a CLI warning; values above `168h` (7 days) are rejected.
  Use `48h` or longer when surviving missed rotation runs, maintenance
  windows, and restart recovery is more important than minimising the
  exposure window.

**Rotation cadence rule:**

Set the `secret_id_ttl` to at least **2× your rotation interval**. This
buffer ensures that a single missed or delayed rotation run does not expire
credentials and leave services unable to re-authenticate.

| Rotation interval | Minimum recommended TTL |
|-------------------|-------------------------|
| 8h                | 16h                     |
| 12h               | 24h (default)           |
| 24h               | 48h                     |

For example, with a 12-hour rotation schedule, the default `24h` TTL
provides exactly one missed-run buffer. If your automation cannot
guarantee timely execution, increase the TTL or shorten the rotation
interval.

**Per-service overrides:**

- `bootroot service add --secret-id-ttl 48h` sets the TTL at issuance time.
- `bootroot service update --secret-id-ttl 48h` changes the stored policy
  (run `bootroot rotate approle-secret-id` afterward to apply).
- Use `--secret-id-ttl inherit` to clear a per-service override and fall
  back to the role-level default.

When `--secret-id-ttl` is omitted during `service add`, the service
inherits the role-level TTL configured during `bootroot init`.

## Updating service secret_id policy

Use `bootroot service update` to change per-service `secret_id` policy
without re-running `service add`:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
bootroot service update --service-name edge-proxy --no-wrap
```

The command modifies `state.json` only. To apply the updated policy to
the actual `secret_id`, run `rotate approle-secret-id` afterward:

```bash
bootroot rotate approle-secret-id --service-name edge-proxy
```

Use `"inherit"` to clear a per-service override and fall back to the
role-level default configured on the AppRole in OpenBao:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl inherit
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

## Remote bootstrap and secret_id handoff operations

For targets added with `--delivery-mode remote-bootstrap`, the operational
model is one-shot bootstrap followed by explicit secret_id handoff:

1. Run `bootroot-remote bootstrap` once on the service machine after
   `bootroot service add` to apply the initial configuration bundle,
   including trust settings and the CA bundle, before the first
   `bootroot-agent` run.
2. After `bootroot rotate approle-secret-id` on the control node, run
   `bootroot-remote apply-secret-id` on the service machine to deliver the
   new secret_id.

Minimum environment/config checklist:

- OpenBao endpoint and KV mount
- service name and AppRole file paths (`role_id`, `secret_id`)
- EAB file path and `agent.toml` path
- profile identity/path fields (hostname, instance_id, cert/key paths)
- CA bundle output path for the managed step-ca trust bundle

Security notes:

- secret directories `0700`, secret files `0600`
- limit service account access to service-specific paths only
- treat `bootroot init --summary-json` output as sensitive because it may
  include `root_token`
- when wrapping is enabled (the default), `bootstrap.json` contains a
  `wrap_token` and must be treated as a sensitive credential file with
  the same handling as `secret_id`

### Idempotent service add rerun

Re-running `bootroot service add` on an existing `remote-bootstrap`
service with the same arguments is idempotent. When wrapping is enabled
(the default), the rerun issues a fresh `secret_id` with wrapping and
regenerates the bootstrap artifact with a new `wrap_token`. The operator
must ship the updated `bootstrap.json` to the remote host and re-run
`bootroot-remote bootstrap`.

If the arguments differ only in policy fields (`--secret-id-ttl`,
`--secret-id-wrap-ttl`, `--no-wrap`), the command rejects the request
and directs the operator to `bootroot service update` instead.

### OpenBao Agent rotation propagation

For `local-file` services, `bootroot rotate approle-secret-id` writes
the new `secret_id` atomically to disk and reloads the per-service
OpenBao Agent. For daemon-mode deployments the agent receives a `SIGHUP`
and re-reads the credential without restarting. For Docker deployments
the agent container is restarted (`docker restart`).

For `remote-bootstrap` services, the rotated `secret_id` is written to
the per-service KV path (`bootroot/services/<service>/secret_id`). The
operator must then run `bootroot-remote apply-secret-id` on the service
machine to deliver it. The service's OpenBao Agent reads the local
`secret_id` file and re-authenticates on the next token renewal cycle.

Note: `bootroot-agent` itself does not re-authenticate with AppRole
directly in the `remote-bootstrap` flow. It consumes the token file that
the OpenBao Agent maintains.

### Wrap token expiry recovery

When wrapping is enabled, the `wrap_token` embedded in `bootstrap.json`
has a limited TTL (default 30 minutes). If the operator does not run
`bootroot-remote bootstrap` before the token expires, the unwrap call
fails with an **expired** error.

Recovery procedure:

1. Re-run `bootroot service add` with the same arguments on the control
   node. Because the service already exists, this is an idempotent rerun
   that issues a fresh `wrap_token`.
2. Ship the updated `bootstrap.json` to the remote host.
3. Run `bootroot-remote bootstrap --artifact <path>` on the remote host.

If the unwrap call fails because the token was **already unwrapped**
(consumed by an unauthorized party), `bootroot-remote` flags the event
as a potential security incident. In this case, rotate the `secret_id`
immediately and investigate the unauthorized access.

## OpenBao restart/recovery checklist

- If OpenBao is `sealed`, unseal it first with unseal keys.
- After unseal, provide runtime auth for operational commands:
  - day-2 `service add`/`rotate`: prefer AppRole (`--auth-mode approle`)
  - bootstrap/break-glass admin tasks: root token (`--auth-mode root`)
- Keep unseal and runtime-auth steps separate in runbooks: unseal completion
  does not satisfy OpenBao auth requirements by itself.

## CA bundle (trust) operations

This section covers how to operate two trust settings together:
`trust.ca_bundle_path` and `trust.trusted_ca_sha256`.

- When `trust.ca_bundle_path` and `trust.trusted_ca_sha256` are configured,
  bootroot-agent splits the ACME issuance response into leaf + chain.
  The leaf cert/key are stored in service paths, and the chain
  (intermediate/root) is written to `trust.ca_bundle_path`.
- If `trust.trusted_ca_sha256` is set, bundle write is allowed only when the
  chain fingerprint check passes. A mismatch fails issuance.
- If the response has no chain, the CA bundle is not updated and a warning
  is logged.
- bootroot-agent normally verifies the ACME server (step-ca) TLS
  certificate. If trust settings are configured, it uses the managed CA
  bundle and pins; otherwise it uses the system CA store.
- CLI override: `bootroot-agent --insecure` disables verification only for
  that run.
- In the managed onboarding flow, trust is prepared before the first
  `bootroot-agent` run:
  - `local-file`: `bootroot service add` writes trust settings and
    `ca-bundle.pem` locally, and the per-service OpenBao Agent keeps them
    synchronized.
  - `remote-bootstrap`: `bootroot service add` writes trust state to
    OpenBao, and `bootroot-remote bootstrap` applies the trust config and
    CA bundle on the service machine.

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

After `trust-sync`:

- `local-file`: the local service host already has the updated trust config
  and bundle on disk.
- `remote-bootstrap`: re-run `bootroot-remote bootstrap` on the service host
  to apply the updated trust payload and CA bundle there.

## Force reissue

To delete a service's certificate and key and trigger bootroot-agent to
reissue:

```bash
bootroot rotate force-reissue --service-name edge-proxy --yes
```

For local services (daemon/docker), the command signals bootroot-agent after
deleting the files. For remote services, it prints a hint to run
`bootroot-remote bootstrap` on the service host.
