# CLI

This document covers the Bootroot automation CLIs (`bootroot` and
`bootroot-remote`).

## Overview

The CLI provides infra bootstrapping, initialization, status checks, service
onboarding, issuance verification, and secret rotation.
It also manages local monitoring with Prometheus and Grafana.
Roles:

- `bootroot`: automates infra/init/service/rotate/monitoring on the
  machine hosting step-ca
- `bootroot-remote`: performs pull/sync/ack convergence on machines
  hosting remote services

Primary commands:

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot service add`
- `bootroot service info`
- `bootroot service sync-status`
- `bootroot verify`
- `bootroot rotate`
- `bootroot monitoring`
- `bootroot-remote pull/ack/sync`

## Global Options

- `--lang`: output language (`en` or `ko`, default `en`)
  - Environment variable: `BOOTROOT_LANG`

## bootroot CLI automation scope vs operator responsibilities

What bootroot CLI installs/starts automatically (Docker path):

- for `bootroot infra up`: image pull plus container create/start for
  OpenBao/PostgreSQL/step-ca/HTTP-01 responder
  (if service images require build, run `docker compose build` separately)
- in the bootroot default topology where step-ca/OpenBao/responder run on one
  machine, `bootroot init` generates step-ca/responder OpenBao Agent configs
  and enables `openbao-agent-stepca`/`openbao-agent-responder` via compose
  override

It does not install host binaries/services (for example, systemd units).

What bootroot CLI prepares automatically:

- service/secret config and state artifacts (`state.json`, per-service
  AppRole/secret files, etc.)
- local config file updates produced by `service add`/`init`/`rotate` flows

What operators must install and manage directly:

- `bootroot` CLI
- `bootroot-agent`
- `bootroot-remote` (CLI that runs on the service machine when an added
  service runs on a different machine from the step-ca host)
- OpenBao Agent

Runtime supervision is also operator-owned:

- systemd mode: configure restart policy (`Restart=always` or `on-failure`)
- container mode: ensure container restart policy and Docker daemon startup on
  reboot

When an added service runs on a different machine from the step-ca host,
schedule `bootroot-remote sync` periodically on that service machine
(systemd timer or cron).

## Name resolution responsibilities

For HTTP-01, step-ca must resolve each validation FQDN
(`<instance>.<service>.<hostname>.<domain>`) to the responder target.

If you use hostnames (instead of direct IPs) for step-ca/responder endpoints,
configure DNS/hosts consistently on every participating host:

- control/step-ca host
- each remote service host

In local Docker E2E, this mapping is injected automatically by test scripts.

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
- `--restart-policy`: container restart policy (default `always`)
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
- `--summary-json`: write init summary as machine-readable JSON
- `--root-token`: OpenBao root token (environment variable: `OPENBAO_ROOT_TOKEN`)
  - required for normal apply mode.
  - optional in preview mode (`--print-only`/`--dry-run`), but required if you
    want trust preview output.
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

DB DSN host handling:

- `localhost`, `127.0.0.1`, and `::1` are normalized to `postgres` during
  init.
- Remote hosts like `db.internal` fail during init because they are not
  reachable from the step-ca container runtime.

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
- DB host resolution summary (`from -> to`)
- EAB registration summary
- OpenBao Agent compose override for step-ca/responder (applied automatically)
- Next-steps guidance
- Optional summary JSON file (`--summary-json`) for automation

### Initial OpenBao Agent auth setup for step-ca/responder

Under the current default topology, OpenBao, step-ca, and responder run on
the machine hosting step-ca and share the local `secrets` directory.

In this default topology, `bootroot init` automatically prepares the initial
OpenBao Agent auth setup for step-ca/responder. The core steps are:

- `bootroot-stepca` and `bootroot-responder` are OpenBao AppRole names, and
  `role_id` is a separate identifier issued by OpenBao for each AppRole
- OpenBao issues `role_id`/`secret_id` for each AppRole
- The issued `role_id`/`secret_id` are written to files read by OpenBao Agent
- OpenBao Agent config (`agent.hcl`) is wired to those files via
  `role_id_file_path`/`secret_id_file_path`
- Applies an additional compose settings file as a compose override on top of
  the base `docker-compose.yml` to enable step-ca/responder OpenBao Agent
  services/config, then starts those agents

This model runs dedicated OpenBao Agent instances instead of running OpenBao
Agent directly inside step-ca/responder processes, and in the default compose
topology those dedicated instances are implemented as separate containers
(`openbao-agent-stepca`, `openbao-agent-responder`). In other words, they are
dedicated agent containers with sidecar-like behavior that run alongside
step-ca/responder in the same compose stack.

Generated auth credential file paths (`role_id`/`secret_id`):

- step-ca:
  `secrets/openbao/stepca/role_id`,
  `secrets/openbao/stepca/secret_id`
- responder:
  `secrets/openbao/responder/role_id`,
  `secrets/openbao/responder/secret_id`

Security expectations:

- secrets directories: `0700`
- secret files (`role_id`/`secret_id` and rendered secrets): `0600`
- local trust boundary on the machine hosting step-ca for this bootstrap model

If OpenBao and step-ca/responder are placed on different machines, the local
`secrets` directory sharing model assumed in this section (file-based secret
delivery) no longer applies. In that case, a separate remote auth-setup process
is required for AppRole credential delivery and agent startup, and this
topology is outside the `bootroot` CLI automation scope.

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

## bootroot service add

Onboards a new service (daemon/docker) so it can obtain certificates from
step-ca by registering its metadata and creating an OpenBao AppRole.
When you run this command, **the `bootroot` CLI** automates:

- Register service metadata in `state.json`
- Create service-scoped OpenBao policy/AppRole and issue `role_id`/`secret_id`
- Write `secrets/services/<service>/role_id` and `secret_id`
- Print execution summary and operator snippets

Automation by `--delivery-mode` choice:

1. `local-file`:
   use this when the service is added on the same machine where
   step-ca/OpenBao/responder are installed. The CLI applies local
   updates (or creates) the managed profile block in `agent.toml` and
   auto-generates OpenBao Agent
   template/config/token files.
2. `remote-bootstrap`:
   use this when the service is added on a different machine from where
   step-ca/OpenBao/responder are installed. The CLI writes a remote sync
   bundle (`secret_id`/`eab`/`responder_hmac`/`trust`) to OpenBao KV and
   generates a remote bootstrap artifact. Here, "remote sync" means
   `bootroot` on the step-ca machine writes the desired config/secret bundle,
   and `bootroot-remote` on the service machine pulls and applies it. The
   "remote bootstrap artifact" is the generated output that contains the
   initial inputs/run information needed to start that remote sync flow.

This is the required step when adding a new service to prepare certificate
issuance/renewal paths. However, `bootroot service add` itself does not issue
certificates.

You still need to perform:

- Start and keep OpenBao Agent/bootroot-agent running on the service machine
- For `remote-bootstrap`, configure periodic `bootroot-remote` runs on the
  service machine
- Validate issuance path via `bootroot verify` or real service startup

In the default flow, a successful `bootroot init` automatically prepares
`secret/bootroot/ca` in OpenBao. Then, in default apply mode (without
`--print-only`/`--dry-run`), `bootroot service add` also handles trust values
automatically as part of onboarding.

- `remote-bootstrap` path: it writes
  `trusted_ca_sha256` into the per-service remote sync bundle
  (`secret/.../services/<service>/trust`), and `bootroot-remote sync`
  applies it to trust settings in `agent.toml` on the service machine.
- `local-file` path: trust settings are auto-merged into `agent.toml`
  (`trusted_ca_sha256` and `ca_bundle_path`), and CA bundle PEM is written
  to the local `ca_bundle_path` when OpenBao trust data includes
  `ca_bundle_pem`.
- bootroot-agent runtime hardening (summary): after first successful issuance
  in normal execution, bootroot-agent auto-writes
  `trust.verify_certificates = true` to `agent.toml` and uses ACME server TLS
  verification from subsequent runs. A run with `--insecure` bypasses
  verification only for that run and skips hardening. For full rules and
  operating flow, see **Configuration > Trust**.

Preview mode note (`--print-only`/`--dry-run`):

- If `--root-token` is provided, preview also queries OpenBao trust data and
  prints trust snippets.
- Without `--root-token`, preview prints why trust snippets are unavailable.

Common cases where manual setup is still needed:

- you want to pin trust fields directly in `agent.toml` for `local-file`
- you apply configuration only from preview output

`--print-only`/`--dry-run` is preview mode: it does not write files/state.

### Runtime deployment policy

#### OpenBao Agent

- Docker service: per-service sidecar (**required**)
- daemon service: per-service daemon (**required**)

#### bootroot-agent

- Docker service: per-service sidecar (recommended)
- daemon service: one shared daemon per host (recommended)

Note: Docker services can use the shared daemon, but this is supported and
not recommended (sidecars provide better isolation/lifecycle alignment).

### Inputs

Input priority is **CLI flags > environment variables > prompts/defaults**.

- `--service-name`: service name identifier
- `--deploy-type`: deployment type (`daemon` or `docker`)
- `--delivery-mode`: delivery mode (`local-file` or `remote-bootstrap`).
  Note: `remote-bootstrap` is a mode value, not an executable binary, and the
  executable used for this mode is `bootroot-remote`.
- `--hostname`: hostname used for DNS SAN
- `--domain`: root domain for DNS SAN
- `--agent-config`: bootroot-agent config path
- `--cert-path`: certificate output path
- `--key-path`: private key output path
- `--instance-id`: service instance_id
- `--container-name`: docker container name (required for docker)
- `--root-token`: OpenBao root token (environment variable: `OPENBAO_ROOT_TOKEN`)
- `--notes`: freeform notes (optional)
- `--print-only`: print snippets/next steps without writing state/files
- `--dry-run`: alias of preview mode (same effect as `--print-only`)

### Interactive behavior

- Prompts for missing required inputs (deploy type defaults to `daemon`).
- Checks that inputs are non-empty, match allowed enum values, and have
  valid paths/parent directories.
- Prints a plan summary before execution and the final summary after.

### Outputs

- App metadata summary
- AppRole/policy/secret_id path summary
- Delivery mode + per-item sync-status summary (`local-file` provides
  auto-applied `agent.toml`/OpenBao Agent config/template paths, and
  `remote-bootstrap` provides a generated bootstrap artifact + ordered remote
  handoff commands)
- Explicit ownership/scope labels in output:
  `Bootroot-managed`, `Operator-managed (required)`,
  `Operator-managed (recommended)`, and
  `Operator-managed (optional)`
- Per-service OpenBao Agent guidance (daemon vs docker)
- Type-specific onboarding guidance (daemon profile / docker sidecar)
- Copy-paste snippets for daemon profile or docker sidecar (default + preview)

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- Duplicate `service-name`
- Missing `instance-id`
- Missing `container-name` for docker
- OpenBao AppRole creation failure

## bootroot service info

Shows onboarding information for a registered service.

### Inputs

- `--service-name`: service name identifier

### Outputs

- App type/paths/AppRole/secret paths summary
- Per-service OpenBao Agent guidance (daemon vs docker)

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- App not found

## bootroot service sync-status

Updates `state.json` sync-status from a `bootroot-remote` summary JSON.
This command is usually called by `bootroot-remote ack`.

### Inputs

- `--service-name`: service name identifier
- `--summary-json`: summary JSON path from `bootroot-remote pull/sync`
- `--state-file`: optional `state.json` path override

### Tracked items

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

### Status values

- `none`: not tracked yet
- `pending`: waiting for remote apply
- `applied`: remote apply acknowledged
- `failed`: apply failed
- `expired`: pending window exceeded and timed out

### Outputs

- Per-item sync-status summary for the target service
- Updated `state.json` (or `--state-file`) metadata/timestamps

### Failure conditions

The command is considered failed when:

- `state.json` is missing or cannot be parsed
- summary JSON is missing or invalid
- target service is not registered

## bootroot verify

Runs a one-shot issuance via bootroot-agent and verifies cert/key output.
Use it after service onboarding or config changes to confirm issuance works.
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
- implementation note: bootroot runs `step crypto change-pass` with `-f`
  (`--force`) to avoid interactive overwrite prompts in non-interactive Docker
  environments.

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

### Rotated secret write targets

For the following three subcommands, bootroot updates OpenBao **and** local
runtime files:

#### `rotate stepca-password`

OpenBao KV: `bootroot/stepca/password`  
Local file: `secrets/password.txt`

#### `rotate db`

OpenBao KV: `bootroot/stepca/db`  
Local file: `secrets/config/ca.json` (`db.dataSource`)

#### `rotate responder-hmac`

OpenBao KV: `bootroot/responder/hmac`  
Local file: `secrets/responder/responder.toml` (`hmac_secret`)

When explicit values are omitted (`--new-password`, `--db-password`, `--hmac`),
bootroot generates new random values.

### Why local file writes are still required

- `step-ca` key password is consumed via `--password-file` in non-interactive
  operation, so `password.txt` must be updated.
- `step crypto change-pass` normally asks overwrite confirmation through
  `/dev/tty`; bootroot passes `-f` to avoid TTY allocation failures in
  containerized, non-interactive runs.
- `step-ca` DB connection is read from `ca.json` (`db.dataSource`), so DSN
  changes must be reflected in that file for runtime use.
- Responder reads `hmac_secret` from its config file.

OpenBao remains the source of truth for rotated values, but these services
still consume local files at runtime.

### Security requirements for local secret files

File-based secrets are acceptable in this model when minimum controls are
enforced:

- secret files: `0600`
- secret directories: `0700`
- least-privilege file ownership
- prevent secret leakage in logs, output, and backups

Risk is not zero: host compromise can still expose local secret files.

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

## bootroot-remote (remote sync binary)

`bootroot-remote` is a separate binary used for services registered with
`bootroot service add --delivery-mode remote-bootstrap`. It applies the desired
service state (`secret_id`/`eab`/`responder_hmac`/`trust`) stored in OpenBao on
the step-ca machine to files on remote service machines via `pull/sync/ack`,
updates local files such as `agent.toml`, and records results in `state.json`
sync-status.

### `bootroot-remote pull`

Pulls and applies service secrets/config to remote file paths.

Key inputs:

- `--openbao-url`, `--kv-mount`, `--service-name`
  - environment variables: `OPENBAO_URL`, `OPENBAO_KV_MOUNT`
- `--role-id-path`, `--secret-id-path`, `--eab-file-path`
- `--agent-config-path`
- baseline/profile inputs:
  `--agent-email`, `--agent-server`, `--agent-domain`,
  `--agent-responder-url`, `--profile-hostname`,
  `--profile-instance-id`, `--profile-cert-path`, `--profile-key-path`
  - `--profile-cert-path` and `--profile-key-path` are optional.
    If omitted, defaults are derived from `--agent-config-path` as
    `certs/<service>.crt` and `certs/<service>.key`.
  - defaults:
    - `--agent-email`: `admin@example.com`
    - `--agent-server`: `https://localhost:9000/acme/acme/directory`
    - `--agent-domain`: `trusted.domain`
    - `--agent-responder-url`: `http://127.0.0.1:8080`
    - `--profile-hostname`: `localhost`
    - `--profile-instance-id`: empty string (`""`)
- `--ca-bundle-path`
  - required to write bundle files when trust data includes `ca_bundle_pem`.
- `--summary-json` (optional) and `--output text|json`

If `agent.toml` does not exist yet, pull creates a baseline config and then
updates (or creates) a managed profile block for the service.

### `bootroot-remote ack`

Acknowledges a summary file back into `state.json` sync-status.

Key inputs:

- `--service-name`
- `--summary-json`
- `--bootroot-bin` (default `bootroot`)
- `--state-file` (optional)

### `bootroot-remote sync`

Runs `pull + ack` with retry/backoff/jitter for scheduled execution.
In production, run this command periodically via systemd timer or cron.

Key retry controls:

- `--retry-attempts`
- `--retry-backoff-secs`
- `--retry-jitter-secs`

Other inputs:

- sync accepts the same pull inputs (`--openbao-url`, `--kv-mount`,
  `--service-name`, `--role-id-path`, `--secret-id-path`, `--eab-file-path`,
  `--agent-config-path`, baseline/profile inputs, `--ca-bundle-path`).
- `--summary-json` is required for sync.
- For ack passthrough, it also accepts `--bootroot-bin` (default `bootroot`)
  and optional `--state-file`.
- It also accepts `--output text|json` for pull-stage output format.

Summary JSON contract items:

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

Each item returns `applied|unchanged|failed` in the pull summary. `ack` maps
that result into `state.json` sync-status values.

Output safety semantics:

- text output redacts per-item error details
- JSON output is machine-readable and should be treated as sensitive artifact
