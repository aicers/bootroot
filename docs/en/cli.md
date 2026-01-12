# CLI

This document covers the bootroot CLI.

## Overview

The CLI provides infra bootstrapping, initialization, and status checks.

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot app add`
- `bootroot app info`
- `bootroot verify`

## Global Options

- `--lang`: output language (`en` or `ko`, default `en`)
  - Environment variable: `BOOTROOT_LANG`

## bootroot infra up

Starts OpenBao/PostgreSQL/step-ca/HTTP-01 responder via Docker Compose and
checks readiness.

### Inputs

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--services`: services to start (default `openbao,postgres,step-ca,bootroot-http01`)
- `--image-archive-dir`: local image archive directory (optional)
- `--restart-policy`: container restart policy (default `unless-stopped`)

### Outputs

- Container status/health summary
- Completion message

### Failures

- docker compose/pull failures
- Missing or unhealthy containers

### Examples

```bash
bootroot infra up
```

## bootroot init

Initializes OpenBao, configures policies/AppRole, initializes step-ca, and
registers required secrets.

### Inputs

- `--openbao-url`: OpenBao API URL (default `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 mount path (default `secret`)
- `--secrets-dir`: secrets directory (default `secrets`)
- `--compose-file`: compose file used for infra checks (default `docker-compose.yml`)
- `--auto-generate`: auto-generate secrets where possible
- `--show-secrets`: show secrets in the summary
- `--root-token`: OpenBao root token
  - Environment variable: `OPENBAO_ROOT_TOKEN`
- `--unseal-key`: OpenBao unseal key (repeatable)
  - Environment variable: `OPENBAO_UNSEAL_KEYS` (comma-separated)
- `--stepca-password`: step-ca password (`password.txt`)
  - Environment variable: `STEPCA_PASSWORD`
- `--db-dsn`: PostgreSQL DSN for step-ca
- `--http-hmac`: HTTP-01 responder HMAC
  - Environment variable: `HTTP01_HMAC`
- `--responder-url`: HTTP-01 responder admin URL (optional)
  - Environment variable: `HTTP01_RESPONDER_URL`
- `--responder-timeout-secs`: responder timeout (seconds, default `5`)
- `--eab-auto`: auto-issue EAB via step-ca
- `--stepca-url`: step-ca URL (default `https://localhost:9000`)
- `--stepca-provisioner`: step-ca ACME provisioner name (default `acme`)
- `--eab-kid`, `--eab-hmac`: manual EAB input

### Outputs

- OpenBao init/unseal summary and AppRole outputs
- `password.txt` and `secrets/config/ca.json` updates
- step-ca init result and responder check status
- EAB registration summary
- Next-steps guidance

### Failures

- Unhealthy infra containers
- OpenBao init/unseal/auth failures
- responder check failures (when enabled)
- step-ca init failures

### Examples

```bash
bootroot init --auto-generate --eab-auto --responder-url http://localhost:8080
```

## bootroot status

Checks infra and OpenBao status.

### Inputs

- `--compose-file`: compose file path
- `--openbao-url`: OpenBao URL
- `--kv-mount`: OpenBao KV v2 mount path
- `--root-token`: token for KV/AppRole checks (optional)

### Outputs

- Container status summary
- OpenBao/KV summary

### Failures

- Missing/unhealthy containers
- OpenBao API unavailable

### Examples

```bash
bootroot status
```

## bootroot app add

Registers app onboarding info and creates an OpenBao AppRole.

### Inputs

- `--app-kind`: app kind identifier
- `--deploy-type`: deployment type (`daemon` or `docker`)
- `--hostname`: hostname used for DNS SAN
- `--domain`: root domain for DNS SAN
- `--agent-config`: bootroot-agent config path
- `--cert-path`: certificate output path
- `--key-path`: private key output path
- `--instance-id`: daemon instance_id (required for daemon)
- `--container-name`: docker container name (required for docker)
- `--root-token`: OpenBao root token
  - Environment variable: `OPENBAO_ROOT_TOKEN`
- `--notes`: freeform notes (optional)

### Outputs

- App metadata summary
- AppRole/policy/secret_id path summary
- Type-specific onboarding guidance (daemon profile / docker sidecar)

### Failures

- Missing `state.json`
- Duplicate `app-kind`
- Missing `instance-id` for daemon
- Missing `container-name` for docker
- OpenBao AppRole creation failure

## bootroot app info

Shows onboarding information for a registered app.

### Inputs

- `--app-kind`: app kind identifier

### Outputs

- App type/paths/AppRole/secret paths summary

### Failures

- Missing `state.json`
- App not found

## bootroot verify

Runs a one-shot issuance via bootroot-agent and verifies cert/key output.

### Inputs

- `--app-kind`: app kind identifier
- `--agent-config`: bootroot-agent config path override (optional)

### Outputs

- cert/key presence
- verification summary

### Failures

- bootroot-agent execution failure
- missing cert/key files
