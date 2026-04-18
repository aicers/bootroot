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
- `bootroot-remote`: performs one-shot bootstrap and explicit secret_id
  handoff on machines hosting remote services

Primary commands:

- `bootroot infra install`
- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot service add`
- `bootroot service update`
- `bootroot service info`
- `bootroot verify`
- `bootroot rotate`
- `bootroot clean`
- `bootroot openbao save-unseal-keys`
- `bootroot openbao delete-unseal-keys`
- `bootroot monitoring`
- `bootroot-remote bootstrap`
- `bootroot-remote apply-secret-id`

## Global Options

- `--lang`: output language (`en` or `ko`, default `en`)
  - Environment variable: `BOOTROOT_LANG`

Notation rule: when an option includes `(environment variable: ...)`, that
option supports environment-variable input. When an option includes
`(default ...)`, a code-level default value is defined. If those markers are
absent, the item either has no default (required/optional input) or does not
support environment-variable input.

## bootroot CLI automation scope vs operator responsibilities

What bootroot CLI installs/starts automatically (Docker workflow):

- for `bootroot infra up`: image pull plus container create/start for
  OpenBao/PostgreSQL/step-ca/HTTP-01 responder, plus replay of HTTP-01
  DNS aliases from `state.json`
  (if service images require build, run `docker compose build` separately)
- for `bootroot service add`: automatic registration of the service's
  HTTP-01 validation FQDN as a Docker network alias on `bootroot-http01`
- in the default topology (OpenBao/PostgreSQL/step-ca/HTTP-01 responder
  deployed on one machine),
  `bootroot init` generates step-ca/responder OpenBao Agent configs and enables
  dedicated OpenBao Agent containers
  (`openbao-agent-stepca`, `openbao-agent-responder`) via compose override

What bootroot CLI prepares automatically:

- service/secret config and state artifacts (`state.json`, per-service
  AppRole/secret files, etc.)
- local config file updates produced by `service add`/`init`/`rotate` flows

What operators must install and manage directly:

- `bootroot` CLI
- `bootroot-agent`
- `bootroot-remote` (CLI that runs on the service machine when an added
  service runs on a different machine from the step-ca host)
- OpenBao Agent (for added services; step-ca/responder agents are auto-prepared
  by `bootroot init`)

Runtime supervision is also operator-owned:

- systemd mode: configure restart policy (`Restart=always` or `on-failure`)
- container mode: ensure container restart policy and Docker daemon startup on
  reboot

When an added service runs on a different machine from the step-ca host,
run `bootroot-remote bootstrap` once on that service machine to apply the
initial configuration bundle, then use `bootroot-remote apply-secret-id`
for explicit secret_id handoff after rotation.

## Name resolution responsibilities

Key points:

- For HTTP-01 validation, step-ca must resolve each service validation FQDN to
  the responder IP. In Docker Compose environments, `bootroot service add`
  registers this alias automatically on `bootroot-http01`.
- If step-ca/responder are accessed by hostname (not direct IP), keep DNS/hosts
  mappings consistent across participating hosts.

For detailed rules and condition-specific behavior, see the Overview section
[/etc/hosts Mapping](index.md#etchosts-mapping).

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
- `--openbao-unseal-from-file`: read OpenBao unseal keys from file
  (dev/test only, environment variable: `OPENBAO_UNSEAL_FILE`)

### Outputs

- Container status/health summary
- Completion message

When a non-loopback OpenBao bind intent is stored in `state.json` (set by
`infra install --openbao-bind`), `infra up` validates that TLS prerequisites
are in place and automatically applies the compose override so OpenBao
listens on the stored address.

### Failure conditions

The command is considered failed when:

- docker compose/pull failures
- Missing or unhealthy containers
- A non-loopback OpenBao bind intent is stored but TLS certificate/key or
  `openbao.hcl` TLS configuration is missing
- A non-loopback OpenBao bind intent is stored but the compose override
  file is missing

### Examples

```bash
bootroot infra up
```

## bootroot infra install

Performs zero-config first-time setup. Generates `.env` with a random
PostgreSQL password, creates `secrets/` and `certs/` directories, and brings
up Docker Compose services (including building local images). This is the
recommended entry point on a fresh clone. Use `bootroot infra up` to restart
an already-configured environment.

### Inputs

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--services`: services to start (default `openbao,postgres,step-ca,bootroot-http01`)
- `--image-archive-dir`: local image archive directory (optional)
- `--restart-policy`: container restart policy (default `always`)
- `--openbao-url`: OpenBao API URL (default `http://localhost:8200`)
- `--openbao-bind <IP>:<port>`: bind OpenBao to a
  non-loopback address for multi-host deployments (optional).
  Records the bind intent in state and generates a compose
  override file. The override is **not** applied during
  `infra install`; it is first applied by `bootroot init` or
  `infra up` after TLS is validated. Default remains
  `127.0.0.1:8200`.
- `--openbao-tls-required`: required acknowledgment flag when
  `--openbao-bind` specifies a non-loopback address.
  Confirms that TLS will be enforced before the non-loopback
  port is published.
- `--openbao-bind-wildcard`: required confirmation flag when
  `--openbao-bind` uses a wildcard address (`0.0.0.0` or
  `[::]`). Without this flag, wildcard binding is rejected.
- `--openbao-advertise-addr <IP>:<port>`: required when
  `--openbao-bind` uses a wildcard address. Specifies the
  routable address that remote bootstrap artifacts will use
  to reach OpenBao. Must be a specific IP (not wildcard or
  loopback). Persisted in `state.json` as
  `openbao_advertise_addr` at install time; the CN-side
  `openbao_url` remains at the install-time loopback URL
  until `bootroot init` rewrites it to the bind-derived
  HTTPS URL after TLS validation.

### Outputs

- Generated `.env` file with random PostgreSQL credentials
- Created `secrets/` and `certs/` directories
- Container status/health summary
- Completion message
- When `--openbao-bind` is used: compose override file at
  `secrets/openbao/docker-compose.openbao-exposed.yml` and
  bind intent recorded in `state.json`

### Failure conditions

The command is considered failed when:

- docker compose build/pull failures
- Missing or unhealthy containers
- `--openbao-bind` format is invalid (must be `<IP>:<port>` with a
  valid IP address)
- `--openbao-bind` with a non-loopback address without
  `--openbao-tls-required`
- `--openbao-bind` with a wildcard address (`0.0.0.0` or `[::]`)
  without `--openbao-bind-wildcard`
- `--openbao-bind` with a wildcard address without
  `--openbao-advertise-addr`

### Examples

```bash
bootroot infra install
```

Multi-host deployment with a specific bind address:

```bash
bootroot infra install --openbao-bind 192.168.1.10:8200 --openbao-tls-required
```

Wildcard binding (requires explicit confirmation and an advertise address):

```bash
bootroot infra install \
  --openbao-bind 0.0.0.0:8200 \
  --openbao-tls-required \
  --openbao-bind-wildcard \
  --openbao-advertise-addr 192.168.1.10:8200
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
- `--enable <feature,...>`: enable optional features (comma-separated).
  Values: `auto-generate`, `show-secrets`, `db-provision`, `db-check`,
  `eab-auto`
- `--skip <phase,...>`: skip optional phases (comma-separated).
  Values: `responder-check`
- `--summary-json`: write init summary as machine-readable JSON
  (it may include sensitive fields such as `root_token`)
- `--root-token`: OpenBao root token (environment variable:
  `OPENBAO_ROOT_TOKEN`). Required for normal apply mode. Optional in preview
  mode (`--print-only`/`--dry-run`), but required if you want trust preview
  output.
  When OpenBao is newly initialized in the current run, init can use the
  generated token in its internal flow without manual token entry. For an
  already-initialized OpenBao, you must provide a token via
  `--root-token`/env/prompt. `bootroot` does not maintain a built-in
  persistent root-token store.
- `--unseal-key`: OpenBao unseal key (repeatable, environment variable: `OPENBAO_UNSEAL_KEYS`)
  You can pass the same option multiple times
  (for example: `--unseal-key k1 --unseal-key k2 --unseal-key k3`).
  For env input, pass a comma-separated list
  (for example: `OPENBAO_UNSEAL_KEYS="k1,k2,k3"`).
- `--openbao-unseal-from-file`: read OpenBao unseal keys from file
  (dev/test only, environment variable: `OPENBAO_UNSEAL_FILE`)
- `--stepca-password`: step-ca password value (stored at `secrets/password.txt`,
  environment variable: `STEPCA_PASSWORD`)
- `--db-dsn`: PostgreSQL DSN for step-ca
- `--db-admin-dsn`: PostgreSQL admin DSN (environment variable: `BOOTROOT_DB_ADMIN_DSN`)
- `--db-user`: PostgreSQL user for step-ca (environment variable: `BOOTROOT_DB_USER`)
- `--db-password`: PostgreSQL password for step-ca (environment variable: `BOOTROOT_DB_PASSWORD`)
- `--db-name`: PostgreSQL database name for step-ca (environment variable: `BOOTROOT_DB_NAME`)
- `--db-timeout-secs`: DB connectivity timeout (seconds, default `2`)
- `--http-hmac`: HTTP-01 responder HMAC (environment variable: `HTTP01_HMAC`)
- `--responder-url`: HTTP-01 responder admin URL (optional, environment
  variable: `HTTP01_RESPONDER_URL`)
- `--responder-timeout-secs`: responder timeout (seconds, default `5`)
- `--stepca-url`: step-ca URL (default `https://localhost:9000`)
- `--stepca-provisioner`: step-ca ACME provisioner name (default `acme`)
- `--cert-duration`: `defaultTLSCertDuration` embedded in the ACME
  provisioner named by `--stepca-provisioner` in `ca.json` /
  `ca.json.ctmpl` (default `24h`, matches step-ca's own default). The
  value is written as a literal in `ca.json.ctmpl` so it survives
  OpenBao Agent render cycles. Must be strictly greater than the
  daemon's `renew_before` (default `16h`); otherwise every newly
  issued certificate is flagged for immediate renewal and init fails
  validation. To change this value after init, use
  `bootroot ca update --cert-duration <value>` followed by
  `bootroot ca restart`.
- `--secret-id-ttl`: role-level `secret_id` TTL for AppRole roles
  created during init (default `24h`). Set this to at least 2× your
  planned rotation interval so that a missed run does not expire
  credentials. `24h` is the security-conservative default; use `48h` or
  longer when operational slack is more important than minimising
  exposure. Values above `48h` emit a warning; values above `168h` are
  rejected. A rotation-cadence reminder is always printed to stderr.
  Per-service overrides can be set later with
  `bootroot service add --secret-id-ttl` or
  `bootroot service update --secret-id-ttl`.
  See [Operations > SecretID TTL and rotation cadence](operations.md#secretid-ttl-and-rotation-cadence).
- `--eab-kid`, `--eab-hmac`: manual EAB input
  (environment variables: `EAB_KID`, `EAB_HMAC`)

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
bootroot init --enable auto-generate,eab-auto --responder-url http://localhost:8080
```

## bootroot status

Checks infra status (including containers) and OpenBao KV/AppRole status.

### Inputs

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--openbao-url`: OpenBao URL (default `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 mount path (default `secret`)
- `--root-token`: token for KV/AppRole checks
  (optional, environment variable: `OPENBAO_ROOT_TOKEN`)
  Without a token, checks are limited to infra/container-level status and do
  not include full KV/AppRole verification.

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
When you run this command, **the `bootroot` CLI** performs onboarding
automation in the following structure.

### 1) Base automation

- Register service metadata in `state.json`
- Create service-scoped OpenBao policy/AppRole and issue `role_id`/`secret_id`
- Write `secrets/services/<service>/role_id` and `secret_id`
- Print execution summary and operator snippets

### 2) Automation by `--delivery-mode`

#### 2-1) `local-file`

- When to use: when the service is added on the same machine where
  OpenBao/PostgreSQL/step-ca/HTTP-01 responder are installed
- Auto-applied: managed profile block update (or create) in `agent.toml`,
  top-level `domain` from `--domain`, `[acme].http_responder_hmac` from
  the responder HMAC stored in OpenBao, local OpenBao Agent
  template/config/token file generation, and HTTP-01 DNS alias registration
  on the `bootroot-http01` container

#### 2-2) `remote-bootstrap`

- When to use: when the service is added on a different machine from where
  OpenBao/PostgreSQL/step-ca/HTTP-01 responder are installed
- Auto-applied: write remote OpenBao KV sync bundle
  (`secret_id`/`eab`/`responder_hmac`/`trust`), generate remote bootstrap
  artifact
- Behavior meaning: `bootroot` on the step-ca machine writes the config/secret
  bundle, and `bootroot-remote` on the service machine pulls and applies it
- Artifact meaning: generated output that contains initial inputs/run
  information required to start remote synchronization

### 3) Command scope and operator actions

- This is the required step to prepare certificate issuance/renewal paths for
  a newly added service.
- `bootroot service add` itself does not issue certificates.

You still need to perform:

- Start and keep OpenBao Agent/bootroot-agent running on the service machine
- For `local-file`, `bootroot service add` already prepares trust files on the
  same host so the first managed `bootroot-agent` run can start in verify mode
- For `remote-bootstrap`, edit the generated `remote run command template`,
  run `bootroot-remote bootstrap` on the service machine before starting
  `bootroot-agent`, and use `bootroot-remote apply-secret-id` after
  secret_id rotation
- Validate issuance path via `bootroot verify` or real service startup

### 4) Trust automation and preview

In the default flow, a successful `bootroot init` automatically prepares
`secret/bootroot/ca` in OpenBao. Then, in default apply mode (without
`--print-only`/`--dry-run`), `bootroot service add` also handles trust values
automatically as part of onboarding.

#### 4-1) Trust automation by delivery mode

- `remote-bootstrap` mode: it writes service trust state into the per-service
  remote bootstrap bundle (`secret/.../services/<service>/trust`), and
  `bootroot-remote bootstrap` applies the trust settings and CA bundle on the
  service machine before the first `bootroot-agent` run.
- `local-file` mode: trust settings are auto-merged into `agent.toml`
  (`trusted_ca_sha256` and `ca_bundle_path`), the CA bundle PEM is written to
  the local `ca_bundle_path`, and the per-service OpenBao Agent keeps them
  synchronized.

#### 4-2) Managed trust bootstrap (summary)

- In the normal managed onboarding flow, both delivery modes prepare trust
  before the first `bootroot-agent` run.
- `local-file`: `bootroot service add` writes trust settings and
  `ca-bundle.pem` locally.
- `remote-bootstrap`: `bootroot service add` prepares the service trust
  payload in OpenBao, and `bootroot-remote bootstrap` applies it on the
  remote host.
- `--insecure` is a per-run break-glass override. For full rules and
  operating flow, see [Configuration > Trust](configuration.md#trust).

#### 4-3) Preview mode (`--print-only`/`--dry-run`)

- If runtime auth is provided (root token or AppRole), preview also queries
  OpenBao trust data and prints trust snippets.
- Without runtime auth, preview prints why trust snippets are unavailable.
- `--print-only`/`--dry-run` is preview mode: it does not write files/state.

#### 4-4) Common manual setup cases

- You want to pin trust fields directly in `agent.toml` for `local-file`.
- You apply configuration only from preview output.

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
  - Must be a single DNS label: letters, digits, and hyphens only, max 63
    characters, no dots or underscores
- `--deploy-type`: deployment type (`daemon` or `docker`)
- `--delivery-mode`: delivery mode (`local-file` or `remote-bootstrap`).
  Note: `remote-bootstrap` is a mode value, not an executable binary, and the
  executable used for this mode is `bootroot-remote`.
- `--hostname`: hostname used for DNS SAN
  - Must follow the same single-label DNS rule as `--service-name`
- `--domain`: root domain for DNS SAN
  - Must be a DNS name made of dot-separated labels; each label uses only
    letters, digits, and hyphens
- `--agent-config`: bootroot-agent config path
- `--cert-path`: certificate output path
- `--key-path`: private key output path
- `--instance-id`: service instance_id
  - Must be numeric (`001`, `42`, ...)
- `--container-name`: docker container name (required for docker)
- `--auth-mode`: runtime auth mode (`auto`, `root`, `approle`, default `auto`)
- `--root-token`: OpenBao root token (environment variable: `OPENBAO_ROOT_TOKEN`,
  transition/break-glass path)
- `--approle-role-id`: OpenBao AppRole role_id
  (environment variable: `OPENBAO_APPROLE_ROLE_ID`)
- `--approle-secret-id`: OpenBao AppRole secret_id
  (environment variable: `OPENBAO_APPROLE_SECRET_ID`)
- `--approle-role-id-file`: file path containing AppRole role_id
  (environment variable: `OPENBAO_APPROLE_ROLE_ID_FILE`)
- `--approle-secret-id-file`: file path containing AppRole secret_id
  (environment variable: `OPENBAO_APPROLE_SECRET_ID_FILE`)
- `--notes`: freeform notes (optional)
- `--print-only`: print snippets/next steps without writing state/files
- `--dry-run`: alias of preview mode (same effect as `--print-only`)

Post-renew hook flags (preset):

- `--reload-style`: reload style preset
  (`sighup`, `systemd`, `docker-restart`, or `none`)
- `--reload-target`: target for the preset
  (process name, systemd unit, or container name)

Presets expand into the following `post_renew` hook
entries in the generated `agent.toml` profile:

- `systemd` + target `nginx` — `systemctl reload nginx`
- `sighup` + target `nginx` — `pkill -HUP nginx`
- `docker-restart` + target `my-container` — `docker restart my-container`
- `none` — no hook

Post-renew hook flags (low-level):

- `--post-renew-command`: hook command to run after successful renewal
- `--post-renew-arg`: hook argument (repeatable)
- `--post-renew-timeout-secs`: hook timeout in seconds (default `30`)
- `--post-renew-on-failure`: failure policy (`continue` or `stop`, default `continue`)

Preset flags (`--reload-style`/`--reload-target`) and
low-level flags (`--post-renew-*`) are mutually
exclusive. When preset flags are used, they expand into
the equivalent low-level hook settings. These flags are
also forwarded to `bootroot-remote bootstrap` for the
`remote-bootstrap` delivery mode.

Per-issuance `secret_id` policy flags:

- `--secret-id-ttl`: TTL for the generated `secret_id` (inherits the
  role-level default when omitted). Should be at least 2× the rotation
  interval
- `--secret-id-wrap-ttl`: response-wrapping TTL for the `secret_id`
  (default `30m`)
- `--no-wrap`: disable response wrapping for the `secret_id`
- `--rn-cidrs`: CIDR ranges to bind the `secret_id` token to
  (repeatable, e.g. `--rn-cidrs 10.0.0.0/24 --rn-cidrs 192.168.1.0/24`).
  When set, OpenBao rejects authentication from source IPs outside the
  specified ranges. Omitting the flag preserves the default (no CIDR
  binding)

These values are persisted in `state.json` and applied on
`rotate approle-secret-id`. `--no-wrap` and `--secret-id-wrap-ttl` control
the same field: `--no-wrap` sets the stored wrap TTL to `0`, disabling
wrapping entirely.

### Interactive behavior

- Prompts for missing required inputs (deploy type defaults to `daemon`).
- Checks that identifiers are non-empty and match the DNS/numeric rules above,
  that enum values are allowed, and that paths/parent directories are valid.
- Prints a plan summary before execution and the final summary after.

### Outputs

- App metadata summary
- AppRole/policy/secret_id path summary
- Delivery mode summary (`local-file` provides
  auto-applied `agent.toml`/OpenBao Agent config/template paths, and
  `remote-bootstrap` provides a generated bootstrap artifact + ordered remote
  handoff command template)
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

## bootroot service update

Modifies per-service `secret_id` policy fields without re-running the
full `service add` flow. At least one policy flag is required.

### Inputs

- `--service-name`: service name identifier
- `--secret-id-ttl`: TTL for the generated `secret_id` (use `"inherit"`
  to clear the per-service override and fall back to the role-level
  default). Should be at least 2× the rotation interval
- `--secret-id-wrap-ttl`: response-wrapping TTL for the `secret_id`
  (use `"inherit"` to restore default wrapping behavior)
- `--no-wrap`: disable response wrapping for the `secret_id`
  (conflicts with `--secret-id-wrap-ttl`)
- `--rn-cidrs`: CIDR ranges to bind the `secret_id` token to
  (repeatable). Use `--rn-cidrs clear` to remove an existing binding

### Behavior

- Reads the service entry from `state.json` and updates only the
  specified policy fields.
- If no fields change, the command exits without writing.
- Prints a summary of before/after values.
- Hints to run `rotate approle-secret-id` to apply the updated policy
  on the next issuance.

### Outputs

- Policy change summary (before → after)
- Next-step guidance

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- Service not found
- No policy flag provided

### Examples

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
bootroot service update --service-name edge-proxy --no-wrap
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

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

## bootroot verify

Runs a one-shot issuance via bootroot-agent and verifies cert/key output.
Use it after service onboarding or config changes to confirm issuance works.
If you want **continuous renewal**, run bootroot-agent in daemon mode
(without `--oneshot`) after verification. Any CLI overrides you pass
(e.g. `--http-responder-hmac`, `--ca-url`) are preserved across
daemon retry cycles, so the daemon behaves the same as `--oneshot`
for those flags.

### Inputs

- `--service-name`: service name identifier
- `--agent-config`: bootroot-agent config path override (optional)
- `--db-check`: verify DB connectivity and auth using ca.json DSN
- `--db-timeout-secs`: DB connectivity timeout (seconds, default `2`)

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
- `rotate trust-sync`
- `rotate force-reissue`
- `rotate ca-key`
- `rotate openbao-recovery`

### Inputs

Common:

- `--state-file`: path to `state.json` (optional)
- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--openbao-url`: OpenBao API URL (optional)
- `--kv-mount`: OpenBao KV mount path (optional)
- `--secrets-dir`: secrets directory (optional)
- `--auth-mode`: runtime auth mode (`auto`, `root`, `approle`, default `auto`)
- `--root-token`: OpenBao root token (env `OPENBAO_ROOT_TOKEN`,
  transition/break-glass path)
- `--approle-role-id`: OpenBao AppRole role_id
  (env `OPENBAO_APPROLE_ROLE_ID`)
- `--approle-secret-id`: OpenBao AppRole secret_id
  (env `OPENBAO_APPROLE_SECRET_ID`)
- `--approle-role-id-file`: file path containing AppRole role_id
  (env `OPENBAO_APPROLE_ROLE_ID_FILE`)
- `--approle-secret-id-file`: file path containing AppRole secret_id
  (env `OPENBAO_APPROLE_SECRET_ID_FILE`)
- `--show-secrets`: print secret-bearing stdout fields in plaintext instead of
  masking them
- `--yes`: skip confirmation prompts

Output behavior:

- By default, rotate subcommands mask secret-bearing stdout fields.
- Use `--show-secrets` only when plaintext stdout is intentionally required.
- This affects secret-bearing summary output such as EAB credentials, root
  tokens, and unseal keys.
- For `rotate openbao-recovery`, `--output` is separate from stdout masking:
  it writes plaintext credentials to the destination file while stdout prints
  only the summary and output path.

Per subcommand:

#### `rotate stepca-password`

- `--new-password`: new step-ca key password (optional, auto-generated if omitted)
- implementation note: bootroot runs `step crypto change-pass` with `-f`
  (`--force`) to avoid interactive overwrite prompts in non-interactive Docker
  environments.

#### `rotate eab`

- `--stepca-url`: step-ca URL (default `https://localhost:9000`)
- `--stepca-provisioner`: ACME provisioner name (default `acme`)
- stdout summary masks EAB `kid` / `hmac` unless `--show-secrets` is set

#### `rotate db`

- `--db-admin-dsn`: DB admin DSN (env `BOOTROOT_DB_ADMIN_DSN`)
- `--db-password`: new DB password
  (optional, auto-generated if omitted, env `BOOTROOT_DB_PASSWORD`)
- `--db-timeout-secs`: DB timeout in seconds (default `2`)

#### `rotate responder-hmac`

- `--hmac`: new responder HMAC (optional, auto-generated if omitted)

#### `rotate approle-secret-id`

- `--service-name`: target service name

#### `rotate trust-sync`

Syncs CA certificate fingerprints and bundle PEM to OpenBao and updates
each service's trust data. For remote services, the trust payload is
written to per-service KV paths. For local services, the agent config
`[trust]` section is updated and the CA bundle PEM is written to disk.

No additional arguments.

#### `rotate force-reissue`

Deletes a service's cert/key files to trigger bootroot-agent to reissue
certificates. For local (daemon) services, sends SIGHUP to the
bootroot-agent process. For Docker services, restarts the container. For
remote services, prints a hint to run `bootroot-remote bootstrap`.

- `--service-name`: target service name

#### `rotate ca-key`

Rotates the CA key pair used by step-ca. By default, only the intermediate
CA key pair is replaced. With `--full`, both root and intermediate CA key
pairs are replaced.

Both modes use an 8-phase idempotent workflow. A `rotation-state.json`
file tracks progress, so re-running after any failure automatically resumes
from the last completed phase. The file also prevents concurrent
modifications.

Phases:

- Phase 0 — Pre-flight: verify required files exist and read current
  fingerprints
- Phase 1 — Backup: back up current cert/key files
- Phase 2 — Generate: create new CA key pair(s) and certificate(s)
- Phase 3 — Additive trust: write transitional trust (old + new
  fingerprints) to OpenBao so services accept both old and new certificates
- Phase 4 — Restart step-ca: restart the step-ca container so it uses the
  new key pair
- Phase 5 — Re-issue: delete service cert/key files and signal
  bootroot-agent (SIGHUP for daemon, container restart for Docker) to
  trigger re-issuance with the new CA. Remote services print a hint instead
- Phase 6 — Finalize trust: write final trust (new fingerprints only) to
  OpenBao, removing old fingerprints
- Phase 7 — Cleanup: delete `rotation-state.json` and optionally remove
  backup files

Intermediate-only mode uses 3-fingerprint transitional trust (old root,
old intermediate, new intermediate). Full mode uses 4-fingerprint
transitional trust (old root, old intermediate, new root, new
intermediate).

Inputs:

- `--full`: rotate both root and intermediate CA keys (default:
  intermediate only)
- `--skip <phase,...>`: skip optional phases (comma-separated).
  Values: `reissue` (Phase 5 — service certificate re-issuance),
  `finalize` (Phase 6 — trust finalization)
- `--force`: force Phase 6 even when un-migrated services remain
- `--cleanup`: delete backup files on completion (Phase 7)

#### `rotate openbao-recovery`

Manually rotates OpenBao recovery credentials. This operation is explicit
operator action only and does not run automatically.

- `--rotate-unseal-keys`: rotate unseal keys via rekey
- `--rotate-root-token`: create a new root token
- `--unseal-key`: existing unseal key (repeatable)
- `--unseal-key-file`: file containing existing unseal keys (one per line)
- `--output`: write new credentials to a file (`0600`)
- stdout summary masks the new root token / unseal keys unless
  `--show-secrets` is set

At least one target flag (`--rotate-unseal-keys` / `--rotate-root-token`)
is required. `rotate openbao-recovery` does not modify AppRole roles,
role_id, or secret_id.

Important behavior:

- `--rotate-unseal-keys` requires existing unseal keys. Provide at least the
  minimum number of key shares configured as the OpenBao unseal threshold,
  using `--unseal-key`, `--unseal-key-file`, or interactive input.
- If existing unseal keys are lost, unseal-key rotation cannot be performed.
  In that case, the practical recovery path is re-initializing OpenBao, which
  implies re-running `bootroot init` and re-bootstrapping services.
- `--rotate-root-token` can be executed without unseal-key input.

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
- runtime auth is missing or invalid (root token or AppRole)
- step-ca password rotation cannot find required key/password files
- DB rotation is missing admin DSN or provisioning fails
- EAB issuance request fails
- responder config write fails or reload fails
- OpenBao recovery rekey/root-token rotation fails
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

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--profile`: `lan` or `public` (default `lan`)
- `--grafana-admin-password`: sets Grafana admin password for **first boot**
  (environment variable: `GRAFANA_ADMIN_PASSWORD`)

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
- You can pass `--compose-file` to target another compose file
  (default `docker-compose.yml`).

### `monitoring down`

Stops and removes monitoring containers without affecting infra.

Inputs:

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--reset-grafana-admin-password`: deletes Grafana data volume so the next
  `monitoring up` can reapply a new admin password

Notes:

- This command auto-detects the running profile(s). It does not accept
  `--profile`.

## bootroot ca update

Updates `defaultTLSCertDuration` on the step-ca ACME provisioner after
initial setup. Patches both `ca.json.ctmpl` (so the new value survives
future OpenBao Agent render cycles) and `ca.json` (so the new value is
in place before the next render cycle).

### Inputs

- `--secrets-dir`: secrets directory (default `secrets`)
- `--stepca-provisioner`: ACME provisioner name whose
  `claims.defaultTLSCertDuration` is updated (default `acme`)
- `--cert-duration`: new `defaultTLSCertDuration` value
  (e.g., `24h`, `48h`). Required.

  `cert-duration` must exceed the `renew_before` value configured in
  `agent.toml` on each agent host; otherwise newly issued certificates
  will be flagged for immediate renewal. The control plane does not
  have access to `agent.toml`, so this cross-validation is not
  performed here — operators are responsible for ensuring consistency.

### Behavior

- Parses and validates the new duration value.
- Writes `claims.defaultTLSCertDuration` onto the ACME provisioner
  named by `--stepca-provisioner` in both `ca.json.ctmpl` and
  `ca.json`. Fails if no ACME provisioner with that name exists.
- Prints a notice that `bootroot ca restart` must be run for step-ca
  to pick up the change.

### Examples

```bash
bootroot ca update --cert-duration 48h
bootroot ca restart
```

## bootroot ca restart

Restarts the step-ca container via Docker Compose so it picks up the
updated `ca.json`. Only the `step-ca` service is restarted; the rest
of the stack is left untouched. After triggering the restart, polls
the container status and returns an error if `step-ca` does not reach
`running` state within 30 seconds.

### Inputs

- `--compose-file`: compose file path (default `docker-compose.yml`)

### Examples

```bash
bootroot ca restart
```

## bootroot clean

Tears down the local environment for a fresh start. Stops containers, removes
volumes, and deletes generated secrets, state, and `.env`. After cleaning,
re-run `bootroot infra install` and `bootroot init` to start over.

### Inputs

- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--yes` / `-y`: skip confirmation prompts

### Behavior

- Runs `docker compose down -v --remove-orphans`
- Removes `secrets/`, `state.json`, `.env`, and optionally `certs/`
- Prompts for confirmation before destructive actions (unless `--yes`)

### Examples

```bash
bootroot clean
```

## bootroot openbao save-unseal-keys

Interactively saves OpenBao unseal keys to a file so that `bootroot infra up`
can auto-unseal on restart (dev/test convenience).

### Inputs

- `--secrets-dir`: secrets directory (default `secrets`)

### Behavior

- Prompts for unseal keys and writes them to the secrets directory
- The saved file is used by `bootroot infra up --openbao-unseal-from-file`

### Examples

```bash
bootroot openbao save-unseal-keys
```

## bootroot openbao delete-unseal-keys

Deletes the previously saved unseal keys file.

### Inputs

- `--secrets-dir`: secrets directory (default `secrets`)

### Examples

```bash
bootroot openbao delete-unseal-keys
```

## bootroot-remote (remote bootstrap binary)

`bootroot-remote` is a separate binary used for services registered with
`bootroot service add --delivery-mode remote-bootstrap`. It performs a one-shot
bootstrap of service state (`secret_id`/`eab`/`responder_hmac`/`trust`) stored
in OpenBao on the step-ca machine to files on remote service machines, and
updates local files such as `agent.toml`. After the initial bootstrap,
`bootroot-remote apply-secret-id` handles explicit secret_id handoff after
rotation.
`bootroot-remote` also supports the global `--lang` option
(environment variable: `BOOTROOT_LANG`).

For an end-to-end walkthrough including transport options (SSH, Ansible,
cloud-init, systemd-credentials), `secret_id` hygiene, and the
`RemoteBootstrapArtifact` schema reference, see the
[Remote Bootstrap Operator Guide](remote-bootstrap.md).

### `bootroot-remote bootstrap`

Performs a one-shot pull and apply of service secrets/config to remote file
paths.

Key inputs:

- `--artifact <path>`: Path to the bootstrap artifact JSON file. When
  provided, artifact values take precedence over per-field CLI flags.
  CLI flags serve as fallbacks for fields absent from the artifact.
  This avoids exposing sensitive `wrap_token` values in shell command
  lines and `ps` output.
  When wrapping is enabled (the default), `bootroot service add` emits
  a command template using `--artifact`.
  If the artifact contains `wrap_token` and `wrap_expires_at` fields,
  `bootroot-remote` unwraps the token via `sys/wrapping/unwrap` to
  obtain `secret_id` before proceeding with the login flow.
- `--openbao-url`: OpenBao API URL (environment variable: `OPENBAO_URL`).
  Required unless `--artifact` is provided.
- `--kv-mount`: OpenBao KV v2 mount path
  (environment variable: `OPENBAO_KV_MOUNT`)
  (default `secret`)
- `--service-name`: required unless `--artifact` is provided.
  - Must follow the same single-label DNS rule as `bootroot service add`
- `--role-id-path`, `--secret-id-path`, `--eab-file-path`: required
  unless `--artifact` is provided.
- `--agent-config-path`: required unless `--artifact` is provided.
- baseline/profile inputs:
  `--agent-email`, `--agent-server`, `--agent-domain`,
  `--agent-responder-url`, `--profile-hostname`,
  `--profile-instance-id`, `--profile-cert-path`, `--profile-key-path`
  - `--agent-domain` must be a DNS name made of dot-separated labels.
  - `--profile-hostname` must be a single DNS label (same rule as
    `--service-name`).
  - `--profile-instance-id` must be numeric. Generated remote handoff command
    templates from `bootroot service add` already set this value.
  - `--profile-cert-path` and `--profile-key-path` are optional.
    If omitted, defaults are derived from `--agent-config-path` as
    `certs/<service>.crt` and `certs/<service>.key`.
  - defaults:
    - `--agent-email`: `admin@example.com`
    - `--agent-server`: `https://localhost:9000/acme/acme/directory`
    - `--agent-domain`: `trusted.domain`
    - `--agent-responder-url`: `http://127.0.0.1:8080`
    - `--profile-hostname`: `localhost`
  - `bootroot service add` prints a `remote run command template` that uses
    the `--artifact` flag. The `--agent-server` and `--agent-responder-url`
    values are baked into the artifact, not passed on the command line. The
    localhost defaults are only correct for same-host setups; on a separate
    service machine, edit `bootstrap.json` and replace them with
    remote-reachable endpoints (e.g., `stepca.internal`,
    `responder.internal`) before transferring the artifact.
- `--ca-bundle-path`: required output path for the managed step-ca trust
  bundle. Required unless `--artifact` is provided.
- post-renew hook flags: `--reload-style`,
  `--reload-target`, `--post-renew-command`,
  `--post-renew-arg`, `--post-renew-timeout-secs`,
  `--post-renew-on-failure` (same semantics as
  `bootroot service add`; passed through from the
  generated remote handoff command template)
- `--summary-json` (optional) and `--output text|json` (default `text`)

If `agent.toml` does not exist yet, bootstrap creates a baseline config and
then updates (or creates) a managed profile block for the service.

### `bootroot-remote apply-secret-id`

Applies a rotated secret_id to the remote service machine. Use this command
after `bootroot rotate approle-secret-id` on the control node to deliver the
new secret_id to the service machine.

Key inputs:

- `--openbao-url`: OpenBao API URL (environment variable: `OPENBAO_URL`)
- `--kv-mount`: OpenBao KV v2 mount path
  (environment variable: `OPENBAO_KV_MOUNT`)
  (default `secret`)
- `--service-name`
  - Must follow the same single-label DNS rule as `bootroot service add`
- `--role-id-path`, `--secret-id-path`
- `--output text|json` (default `text`)

Output safety semantics:

- text output redacts per-item error details
- JSON output is machine-readable and should be treated as sensitive artifact
