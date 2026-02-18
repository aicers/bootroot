# Operations

This section focuses on runbook checks and avoids repeating setup details.
See **Installation** and **Configuration** for full setup steps and options.
If you are using the CLI, see `docs/en/cli.md`. This document focuses on the
**manual operations** flow.

For CI/test operations, see [CI & E2E](e2e-ci.md).

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

## Rotation scheduling

Run `bootroot rotate ...` on a schedule (cron/systemd timer). Keep secrets out
of command history; use environment files or secure stores.

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

## Remote sync runner operations

For remote-bootstrap services, run a periodic `bootroot-remote sync` runner.
Template files are provided:

- `scripts/bootroot-remote-sync.service`
- `scripts/bootroot-remote-sync.timer`
- `scripts/bootroot-remote-sync.cron`

Recommended pattern:

- one runner per service
- one `--summary-json` file per service
- keep role/secret/token/config paths service-scoped

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

Security notes:

- secret directories `0700`, secret files `0600`
- avoid printing raw summary JSON with secrets to shared logs
- limit service account access to service-specific paths only

## CA bundle (trust) operations

When `trust` is enabled, bootroot-agent **splits the leaf and chain** from the
ACME response, stores the leaf cert/key, and writes the chain (intermediate/root)
to `ca_bundle_path`. This bundle is used for mTLS peer verification.

- `trust.ca_bundle_path` is the **CA bundle output path**.
- If `trust.trusted_ca_sha256` is set, the response chain **must pass
  fingerprint verification** or issuance fails.
- If no chain is present, the CA bundle is not written (logged).
- With `trust.verify_certificates = true`, bootroot-agent verifies the ACME
  server TLS certificate. If `ca_bundle_path` is set, it uses that bundle;
  otherwise it uses the system CA store.
- CLI override: `bootroot-agent --verify-certificates` or `--insecure`.

Permissions/ownership:

- The **service consuming** the CA bundle must be able to read the file.
- The simplest setup is running bootroot-agent and the service as the **same
  user or group**.
