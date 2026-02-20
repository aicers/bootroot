# Troubleshooting

This page lists high-frequency failures.
Use [CLI](cli.md) for command/option definitions, [CLI Examples](cli-examples.md)
for concrete runs, and [CI & E2E](e2e-ci.md) for validation scenarios.

## Common first checks

- Verify which binary you are running (`bootroot`, `bootroot-agent`, `bootroot-remote`)
- Use `--help` on the exact binary/version you are invoking
- Verify OpenBao/step-ca/PostgreSQL/responder processes are actually running
- Verify name-to-IP mapping (`/etc/hosts` or DNS) matches your topology

## "error: unexpected argument"

The most common cause is mixing flags across binaries.

- `bootroot` flags are different from `bootroot-agent` flags.
- `bootroot-remote` has its own flag set.
- Check `--help` on the specific binary before retrying.

## `bootroot infra up` / `bootroot init` failures

### OpenBao failures

- Check whether OpenBao is still `sealed` and unseal if needed
- Verify root token/AppRole credentials
- Confirm KV v2 mount exists (default `secret`)
- Unseal keys and root token have different roles:
  - unseal keys: clear `sealed` state
  - root token: privileged commands (`service add`, `rotate`, detailed status)

### root token missing/invalid

Symptoms:

- `root token missing` or permission-related errors

Checks:

- Confirm the current command requires root token
- Verify `--root-token`/`OPENBAO_ROOT_TOKEN` value and expiry
- If this is a detailed status/trust preview flow, confirm mode-specific token
  requirements

Actions:

- Re-inject token from a secure store or protected env file
- Keep runbooks explicit that `bootroot` does not provide a built-in persistent
  root-token store

### step-ca init / CA file failures

Missing files below can fail init:

- `secrets/certs/root_ca.crt`
- `secrets/certs/intermediate_ca.crt`

### PostgreSQL DSN failures

If you see `dial tcp 127.0.0.1:5432: connect: connection refused`, DSN host in
`secrets/config/ca.json` is often wrong for container runtime.

- `localhost`/`127.0.0.1`/`::1` input should be normalized to `postgres`
- Remote hosts like `db.internal` fail by design under single-host guardrails
- Check init summary DB host conversion line (`from -> to`)

### responder check failures

- step-ca must reach responder `:80`
- responder admin API (`:8080`) path must be correct

## `bootroot service add` result differs from expectation

### Distinguish preview and apply modes

- `--print-only` / `--dry-run` is preview mode
- Preview mode does not write files/state
- Trust preview may require `--root-token` even in preview mode

### Verify delivery mode (`--delivery-mode`)

- `local-file`: service is added on the same machine as step-ca/OpenBao/responder
- `remote-bootstrap`: service is added on another machine and applied through
  `bootroot-remote`

If mode and placement do not match, file/state updates go to the wrong path.

## `remote-bootstrap` sync failures

- Ensure `bootroot-remote sync` is configured as a periodic run on service hosts
- Use a unique `--summary-json` path per service for concurrent syncs
- Compare these two outputs
  - `bootroot-remote sync --summary-json ...`
  - `bootroot service sync-status` on the control machine

If only one side changes, the flow is usually broken in `pull/sync/ack`.

## Issuance and renewal failures

### HTTP-01 failures

- step-ca must map service FQDN to responder IP
- service hosts (remote mode) must also map step-ca/responder names correctly

### `Finalize failed: badCSR`

- Requested SANs do not match step-ca provisioner policy
- Validate both SAN generation and CA policy together

### Repeated ACME directory retries

- Ensure `server` URL is `https://` (`http://` is rejected)
- Validate system trust or `trust.ca_bundle_path`
- Use `bootroot-agent --insecure` only for temporary diagnosis

### Auto-hardening failed after issuance

- Symptom: issuance succeeded, but bootroot-agent exits non-zero right after.
- Cause: writing/reloading `agent.toml` for
  `trust.verify_certificates = true` failed.
- Check `--config` path, file permissions, and config syntax.

## File and hook errors

- Check parent directory existence and write permission for `profiles.paths`
- Verify runtime user permissions
- For hook failures, verify `command` path/permissions and `working_dir`
- Check logs for truncation warnings on process output

## Local E2E-only failures

- `hosts-all` needs host `/etc/hosts` mutation, so `sudo -n` is required
- If `sudo -n` is unavailable locally, use `--skip-hosts-all`
- This is a local workaround; CI still validates `hosts-all`
