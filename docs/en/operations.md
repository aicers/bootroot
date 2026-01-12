# Operations

This section focuses on runbook checks and avoids repeating setup details.
See **Installation** and **Configuration** for full setup steps and options.
If you are using the CLI, see `docs/en/cli.md`. This document focuses on the
**manual operations** flow.

## bootroot-agent

- Monitor logs for issuance, authorization, and hook results.
- Ensure key/secret permissions stay `0600`/`0700` on disk.
- Use hooks to reload dependent services after renewals
  (hook definitions live in **Configuration**).

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
