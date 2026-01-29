# Troubleshooting

If you are using the CLI, see `docs/en/cli.md`. This document focuses on the
**manual operations** flow.

## "error: unexpected argument" at startup

Check your CLI flags. The current CLI supports:

- `--config`
- `--email`
- `--ca-url`
- `--eab-kid` / `--eab-hmac` / `--eab-file`
- `--oneshot`

## OpenBao connection/auth failures

- Check whether OpenBao is sealed
- Verify the root token or AppRole credentials
- Confirm the KV v2 mount exists

## OpenBao KV v2 errors

- Ensure KV v2 is enabled (default mount `secret`)
- If using a different mount, pass it via CLI or env

## HTTP-01 challenge fails

- Ensure port 80 is reachable from step-ca to the responder
- Verify the responder is running and bound to port 80
- Confirm the domain resolves to the responder host
- Check the agent can reach the responder admin API (port 8080)

## step-ca PostgreSQL connection failures

If you see errors like `dial tcp 127.0.0.1:5432: connect: connection refused`,
`db.dataSource` in `secrets/config/ca.json` is likely pointing to localhost
inside the container. In Compose, use the service name (for example,
`postgres`) instead of `127.0.0.1` or `localhost`.

Restart step-ca after updating the DSN.

## "Finalize failed: badCSR"

This usually means the CSR SANs are not accepted by the CA policy.
Check the step-ca provisioner policy and the requested DNS SAN.

## Certificate files not written

- Check permissions of `profiles.paths` directories
- Ensure the parent directory exists
- Verify the user running bootroot-agent can write

## "CA certificate not found" errors

`bootroot init` stores CA fingerprints in OpenBao and requires
`secrets/certs/root_ca.crt` and `secrets/certs/intermediate_ca.crt`. If those
files are missing, init fails.

- Confirm step-ca initialization completed
- Ensure the files exist under `secrets/certs/`

## ACME directory fetch retries

- Confirm step-ca is up and reachable
- Check TLS trust for the CA endpoint:
  - If using system trust, ensure the CA is installed in the OS store
  - If using `trust.ca_bundle_path`, ensure the bundle exists and is readable
  - For temporary diagnosis, use `bootroot-agent --insecure` (not for prod)
- Verify `server` URL in `agent.toml`

## Hook execution errors

- Confirm `command` path and permissions
- Check `working_dir` exists
- Look for log messages about stdout/stderr truncation
- Review logs for output truncation messages
