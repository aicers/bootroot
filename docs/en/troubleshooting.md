# Troubleshooting

## "error: unexpected argument" at startup

Check your CLI flags. The current CLI supports:

- `--config`
- `--email`
- `--ca-url`
- `--eab-kid` / `--eab-hmac` / `--eab-file`
- `--oneshot`

## HTTP-01 challenge fails

- Ensure port 80 is reachable from step-ca to the responder
- Verify the responder is running and bound to port 80
- Confirm the domain resolves to the responder host
- Check the agent can reach the responder admin API (port 8080)

## "Finalize failed: badCSR"

This usually means the CSR SANs are not accepted by the CA policy.
Check the step-ca provisioner policy and the requested domains.

## Certificate files not written

- Check permissions of `profiles.paths` directories
- Ensure the parent directory exists
- Verify the user running bootroot-agent can write

## ACME directory fetch retries

- Confirm step-ca is up and reachable
- Check TLS trust for the CA endpoint
- Verify `server` URL in `agent.toml`

## Hook execution errors

- Confirm `command` path and permissions
- Check `working_dir` exists
- Look for log messages about stdout/stderr truncation
- Review logs for output truncation messages
