# CLI

This document covers the bootroot CLI.

## Overview

The CLI provides infra bootstrapping, initialization, status checks, app
onboarding, issuance verification, and secret rotation.
It also manages local monitoring with Prometheus and Grafana.

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot app add`
- `bootroot app info`
- `bootroot verify`
- `bootroot rotate`
- `bootroot monitoring`

## Global Options

- `--lang`: output language (`en` or `ko`, default `en`)
  - Environment variable: `BOOTROOT_LANG`

## bootroot infra up

Starts OpenBao/PostgreSQL/step-ca/HTTP-01 responder via Docker Compose and
checks readiness.
This command assumes OpenBao/PostgreSQL/HTTP-01 responder run on the **same
machine as step-ca**. If you deploy them on separate machines, use manual
setup instead of the CLI.

### Inputs

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--services`: services to start (default `openbao,postgres,step-ca,bootroot-http01`)
- `--image-archive-dir`: local image archive directory (optional)
- `--restart-policy`: container restart policy (default `unless-stopped`)
- `--openbao-url`: OpenBao API URL (default `http://localhost:8200`)
- `--openbao-unseal-from-file`: read OpenBao unseal keys from file (dev/test only)

### Outputs

- Container status/health summary
- Completion message

### Failure conditions

The command is considered failed when:

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

Input priority is **CLI flags > environment variables > prompts/defaults**.

- `--openbao-url`: OpenBao API URL (default `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 mount path (default `secret`)
- `--secrets-dir`: secrets directory (default `secrets`)
- `--compose-file`: compose file used for infra checks (default `docker-compose.yml`)
- `--auto-generate`: auto-generate secrets where possible
- `--show-secrets`: show secrets in the summary
- `--root-token`: OpenBao root token (environment variable: `OPENBAO_ROOT_TOKEN`)
- `--unseal-key`: OpenBao unseal key (repeatable, environment variable: `OPENBAO_UNSEAL_KEYS`)
- `--openbao-unseal-from-file`: read OpenBao unseal keys from file (dev/test only)
- `--stepca-password`: step-ca password (`password.txt`, environment variable: `STEPCA_PASSWORD`)
- `--db-dsn`: PostgreSQL DSN for step-ca
- `--db-provision`: provision PostgreSQL role/database for step-ca
- `--db-admin-dsn`: PostgreSQL admin DSN (environment variable: `BOOTROOT_DB_ADMIN_DSN`)
- `--db-user`: PostgreSQL user for step-ca (environment variable: `BOOTROOT_DB_USER`)
- `--db-password`: PostgreSQL password for step-ca (environment variable: `BOOTROOT_DB_PASSWORD`)
- `--db-name`: PostgreSQL database name for step-ca (environment variable: `BOOTROOT_DB_NAME`)
- `--db-check`: validate DB connectivity and auth
- `--db-timeout-secs`: DB connectivity timeout (seconds)
- `--http-hmac`: HTTP-01 responder HMAC (environment variable: `HTTP01_HMAC`)
- `--responder-url`: HTTP-01 responder admin URL (optional, environment
  variable: `HTTP01_RESPONDER_URL`)
- `--skip-responder-check`: skip responder check during init (for constrained
  test environments)
- `--responder-timeout-secs`: responder timeout (seconds, default `5`)
- `--eab-auto`: auto-issue EAB via step-ca
- `--stepca-url`: step-ca URL (default `https://localhost:9000`)
- `--stepca-provisioner`: step-ca ACME provisioner name (default `acme`)
- `--eab-kid`, `--eab-hmac`: manual EAB input

### Interactive behavior

- Prompts for missing required inputs.
- Checks that inputs are non-empty, match allowed enum values, and have
  valid paths/parent directories.
- Confirms before overwriting `password.txt`, `ca.json`, or `state.json`.
- Prints a plan summary before execution and the final summary after.

### Outputs

- OpenBao init/unseal summary and AppRole outputs
- `password.txt` and `secrets/config/ca.json` updates
- step-ca init result and responder check status
- DB connectivity check status (when enabled)
- EAB registration summary
- OpenBao Agent compose override for step-ca/responder (applied automatically)
- Next-steps guidance

### Failure conditions

The command is considered failed when:

- Unhealthy infra containers
- OpenBao init/unseal/auth failures
- responder check failures (when enabled)
- step-ca init failures

### Examples

```bash
bootroot init --auto-generate --eab-auto --responder-url http://localhost:8080
```

## bootroot status

Checks infra status (including containers) and OpenBao KV/AppRole status.

### Inputs

- `--compose-file`: compose file path
- `--openbao-url`: OpenBao URL
- `--kv-mount`: OpenBao KV v2 mount path
- `--root-token`: token for KV/AppRole checks (optional)

### Outputs

- Container status summary
- OpenBao/KV summary

### Failure conditions

The command is considered failed when:

- Missing/unhealthy containers
- OpenBao API unavailable

### Examples

```bash
bootroot status
```

## bootroot app add

Onboards a new app (daemon/docker) so it can obtain certificates from
step-ca by registering its metadata and creating an OpenBao AppRole.
When you run this command, **the bootroot CLI** performs:

- Save app metadata (service name, deploy type, hostname, domain, etc.)
- Create AppRole/policy and issue `role_id`/`secret_id`
- Prepare app secret paths and required file locations
- Print run guidance for bootroot-agent and OpenBao Agent

This is the required step when adding a new app. After it completes, you
must run bootroot-agent and OpenBao Agent as instructed, and then start
the app so mTLS certificates are used correctly in app-to-app traffic.

`bootroot app add` does not issue certificates by itself. To actually obtain
certificates from step-ca, you must **configure and run bootroot-agent**.
See the bootroot-agent sections in the manuals (Installation/Operations/
Configuration) for details.

If `bootroot init` stored CA fingerprints in OpenBao (for example,
`secret/bootroot/ca`), this command includes `trusted_ca_sha256` in the
agent.toml snippet output. If the value is missing, you must set it manually
when needed.

If the app runs on a different machine, the bootroot-agent on that host
must use the same `agent.toml`. The `--cert-path`/`--key-path` values must
also be set relative to where the app runs. This command only prints
paths/snippets; you still configure and run the agent on the machine where
the app runs.

### Inputs

Input priority is **CLI flags > environment variables > prompts/defaults**.

- `--service-name`: service name identifier
- `--deploy-type`: deployment type (`daemon` or `docker`)
- `--hostname`: hostname used for DNS SAN
- `--domain`: root domain for DNS SAN
- `--agent-config`: bootroot-agent config path
- `--cert-path`: certificate output path
- `--key-path`: private key output path
- `--instance-id`: app instance_id
- `--container-name`: docker container name (required for docker)
- `--root-token`: OpenBao root token (environment variable: `OPENBAO_ROOT_TOKEN`)
- `--notes`: freeform notes (optional)

### Interactive behavior

- Prompts for missing required inputs (deploy type defaults to `daemon`).
- Checks that inputs are non-empty, match allowed enum values, and have
  valid paths/parent directories.
- Prints a plan summary before execution and the final summary after.

### Outputs

- App metadata summary
- AppRole/policy/secret_id path summary
- Per-app OpenBao Agent guidance (daemon vs docker)
- Type-specific onboarding guidance (daemon profile / docker sidecar)
- Copy-paste snippets for daemon profile or docker sidecar

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- Duplicate `service-name`
- Missing `instance-id`
- Missing `container-name` for docker
- OpenBao AppRole creation failure

## bootroot app info

Shows onboarding information for a registered app.

### Inputs

- `--service-name`: service name identifier

### Outputs

- App type/paths/AppRole/secret paths summary
- Per-app OpenBao Agent guidance (daemon vs docker)

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- App not found

## bootroot verify

Runs a one-shot issuance via bootroot-agent and verifies cert/key output.
Use it after app onboarding or config changes to confirm issuance works.
If you want **continuous renewal**, run bootroot-agent in daemon mode
(without `--oneshot`) after verification.

### Inputs

- `--service-name`: service name identifier
- `--agent-config`: bootroot-agent config path override (optional)
- `--db-check`: verify DB connectivity and auth using ca.json DSN
- `--db-timeout-secs`: DB connectivity timeout (seconds)

### Interactive behavior

- Prompts for missing required inputs.
- Checks that inputs are not empty.
- Prints a plan summary before execution and the final summary after.

### Outputs

- cert/key presence
- verification summary
- DB connectivity check status (when enabled)

### Failure conditions

The command is considered failed when:

- bootroot-agent execution failure
- missing cert/key files

## bootroot rotate

Runs secret rotation workflows. It uses `state.json` to locate paths and
updates values through OpenBao.

Supported subcommands:

- `rotate stepca-password`
- `rotate eab`
- `rotate db`
- `rotate responder-hmac`
- `rotate approle-secret-id`

### Inputs

Common:

- `--state-file`: path to `state.json` (optional)
- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--openbao-url`: OpenBao API URL (optional)
- `--kv-mount`: OpenBao KV mount path (optional)
- `--secrets-dir`: secrets directory (optional)
- `--root-token`: OpenBao root token (env `OPENBAO_ROOT_TOKEN`)
- `--yes`: skip confirmation prompts

Per subcommand:

#### `rotate stepca-password`

- `--new-password`: new step-ca key password (optional, auto-generated if omitted)

#### `rotate eab`

- `--stepca-url`: step-ca URL
- `--stepca-provisioner`: ACME provisioner name

#### `rotate db`

- `--db-admin-dsn`: DB admin DSN (env `BOOTROOT_DB_ADMIN_DSN`)
- `--db-password`: new DB password (optional, auto-generated if omitted)
- `--db-timeout-secs`: DB timeout in seconds

#### `rotate responder-hmac`

- `--hmac`: new responder HMAC (optional, auto-generated if omitted)

#### `rotate approle-secret-id`

- `--service-name`: target service name

### Outputs

- Rotation summary (updated files/configs)
- Restart/reload guidance (step-ca restart, responder reload, etc.)
- AppRole secret_id rotation includes OpenBao Agent reload and login check

### Failure conditions

The command is considered failed when:

- `state.json` is missing or cannot be parsed
- OpenBao is unreachable or unhealthy
- root token is missing or invalid
- step-ca password rotation cannot find required key/password files
- DB rotation is missing admin DSN or provisioning fails
- EAB issuance request fails
- responder config write fails or reload fails
- AppRole target is missing or secret_id update fails

## bootroot monitoring

Manages the local monitoring stack (Prometheus + Grafana) that is defined in
`docker-compose.yml`. Monitoring uses compose profiles to separate LAN and
public access modes.

Supported subcommands:

- `monitoring up`
- `monitoring status`
- `monitoring down`

### Profiles

- `lan`: Grafana binds to `GRAFANA_LAN_BIND_ADDR` (default `127.0.0.1`)  
  The default is **localhost-only**, so access is limited to the same machine.  
  Here, “LAN IP” means the **private-network interface IP** on the same host  
  (for example, `192.168.x.x` or `10.x.x.x`).  
  Binding to a LAN IP allows access **only within that private network**  
  segment and prevents access from the public internet  
  (assuming no routing or port forwarding).
- `public`: Grafana binds to `0.0.0.0`  
  **All interfaces are reachable**, so access is possible from the same LAN  
  and from outside networks.
  - Access URL: `http://<public-ip>:3000`

### `monitoring up`

Starts Prometheus and Grafana for the selected profile.

Inputs:

- `--profile`: `lan` or `public` (default `lan`)
- `--grafana-admin-password`: sets Grafana admin password for **first boot**
  (can also be passed via `GRAFANA_ADMIN_PASSWORD`)

Behavior:

- If monitoring is already running, it prints a message and exits.
- Password override is only applied on first boot (Grafana stores it in its DB).

Access URLs:

- `lan`: `http://<lan-ip>:3000` (or `http://127.0.0.1:3000` if using default)
- `public`: `http://<public-ip>:3000`

### `monitoring status`

Prints monitoring service health plus Grafana access details.

Outputs:

- Service status/health for Prometheus and Grafana
- Grafana URL (based on profile + `GRAFANA_LAN_BIND_ADDR`)
- Admin password status:
  - `default (admin)`, `set`, or `unknown`

Notes:

- This command auto-detects the running profile(s). It does not accept
  `--profile`.

### `monitoring down`

Stops and removes monitoring containers without affecting infra.

Inputs:

- `--reset-grafana-admin-password`: deletes Grafana data volume so the next
  `monitoring up` can reapply a new admin password

Notes:

- This command auto-detects the running profile(s). It does not accept
  `--profile`.
