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
- `bootroot-remote`: performs one-shot bootstrap on machines hosting remote
  services (its `apply-secret-id` subcommand is a recovery path for an agent
  that was offline past its `secret_id_ttl`)

Primary commands:

- `bootroot infra install`
- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot service add`
- `bootroot service update`
- `bootroot service remove`
- `bootroot service info`
- `bootroot service openbao-sidecar start`
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
initial configuration bundle and start `bootroot-agent`. The running agent
then keeps itself current via its fast-poll loop: it pulls trust and
`secret_id` rotations from OpenBao and re-renders `agent.toml` without
operator action, so no second daemon (OpenBao Agent sidecar) runs on the
remote host. `bootroot-remote apply-secret-id` and re-running
`bootroot-remote bootstrap` are recovery paths only — needed when an agent
was offline past its `secret_id_ttl` and its credential already expired.

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
- `--postgres-host-port <N>`: host-side `PostgreSQL` published port.
  Overrides `POSTGRES_HOST_PORT` from `.env` and the process
  environment. When unset, the published default is **5433** so
  bootroot does not claim the conventional 5432 out of the box.

Before invoking `docker compose up`, `infra install` runs a TCP bind
preflight on every host-side port the active compose stack publishes
(`PostgreSQL`, `OpenBao`, `step-ca`, `bootroot-http01`). On collision
it aborts with the busy port, a best-effort PID/command hint via
`lsof`, and the recommended remediation, instead of leaving earlier
services running while a later one fails to bind (#588 §4). The
preflight always checks the localhost ports because `infra install`
runs `docker compose up` against the base compose file only —
`--openbao-bind` / `--http01-admin-bind` / `--stepca-bind` write
override files for `infra up` / `init` but are not layered into the
install-time `up`.

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
  Values: `auto-generate`, `show-secrets`, `db-provision`, `db-check`
- `--skip <phase,...>`: skip optional phases (comma-separated).
  Values: `responder-check`
- `--summary-json`: write init summary as machine-readable JSON
  (it may include sensitive fields such as `root_token`). The path is
  preflight-checked before any OpenBao work begins: init refuses to
  start if the path is a directory, an unwritable existing file, a
  world-/group-readable existing file, or sits under an uncreatable or
  read-only parent. This avoids the partial-init trap in which init
  completes against OpenBao and only then fails to write the summary,
  leaving the freshly issued root token and unseal keys captured
  nowhere.
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
- `--rotate-bound-cidrs`: CIDR ranges to bind the two rotate AppRole
  credentials (`bootroot-runtime-rotate-role`,
  `bootroot-infra-rotate-role`) to (repeatable, e.g.
  `--rotate-bound-cidrs 10.0.0.5/32`). Recorded in `state.json` and
  re-applied to every self-minted rotate `secret_id`. Supply the source
  IP OpenBao sees for the control-plane host — it varies by deployment
  mode, so bootroot never auto-derives it; omitted means no binding
  (opt-in). Host-boundary control, not process isolation. See
  [Operations > The rotate credentials' own secret_ids (self-mint)](operations.md#the-rotate-credentials-own-secret_ids-self-mint).
- `--eab-kid`, `--eab-hmac`: manual EAB input
  (environment variables: `EAB_KID`, `EAB_HMAC`). When both are
  provided, init validates them (non-empty `kid`; `hmac` must
  base64url-decode to at least 16 bytes) and forwards them to the
  ACME `newAccount` request. The bundled OSS step-ca does not support
  EAB, so these flags apply only when targeting an EAB-capable CA
  (for example, a commercial Smallstep Certificate Manager
  deployment). The interactive EAB prompt re-prompts on validation
  failure rather than silently accepting garbage (#588 §3a).
- `--no-eab`: skip the EAB prompt and persist no EAB credentials.
  Conflicts with `--eab-kid`/`--eab-hmac`. Recommended for OSS
  step-ca and CI flows that never use EAB (#588 §3b).
- `--save-unseal-keys`: skip the "Save unseal keys to file?" prompt and
  persist the freshly generated unseal keys to
  `<secrets_dir>/openbao/unseal-keys.txt` (mode `0600`). Equivalent to
  answering `y` at the prompt. Conflicts with `--no-save-unseal-keys`
  (#603).
- `--no-save-unseal-keys`: skip the "Save unseal keys to file?" prompt
  and do NOT persist the keys to that on-disk path. Requires
  `--summary-json <path>` so the freshly generated keys are captured in
  the 0600 summary file; without it the keys would be lost and would
  brick the next OpenBao restart. Under this flag the cleartext-echo
  fallback is also suppressed (the keys are already in the summary
  JSON, and echoing would leak them into CI logs). Conflicts with
  `--save-unseal-keys` (#603).

If a previous `init` failed mid-flight and rolled back, OpenBao may
remain initialised in its volume while bootroot has no usable root
token. `init` detects this state on startup and emits an actionable
diagnostic naming three recovery paths (re-supply
`--root-token`/`OPENBAO_ROOT_TOKEN`, run `bootroot clean
--openbao-only`, or perform manual operator action) instead of
bubbling up an opaque `403 permission denied` (#588 §5a).

When `init` provisions the runtime database role/database (i.e. the
`db-provision` feature is enabled), it grants `CREATE, USAGE` on the
target database's `public` schema to the runtime role and persists
the admin DSN it used to a high-privilege OpenBao KV path
(`bootroot/stepca/db_admin`). `bootroot rotate db` reads from that
path so the operator no longer has to pass `--db-admin-dsn` on every
rotation. This KV path is intentionally readable only by
operator/root tokens, not by the runtime AppRole policy. After
`init`'s post-bootstrap `.env` password rotation runs, the persisted
admin DSN is rewritten with the new password whenever the admin user
matches the runtime user being rotated (the bundled same-role
topology); the rotation also resolves the host-side Postgres port
from the compose dir's `.env` / process env (same precedence Docker
Compose uses for `${POSTGRES_HOST_PORT:-5433}`) so the new 5433
default does not silently skip the rotation. The auto-derived
admin DSN built when `--db-admin-dsn` is not supplied (from
`POSTGRES_USER` / `POSTGRES_PASSWORD` in the compose `.env`)
follows the same `${POSTGRES_HOST_PORT:-5433}` precedence for its
port and defaults its host to `127.0.0.1` rather than the
compose-internal `postgres` so the host-side `provision_db_sync`
can reach it on the published port (#588 §1, §2).

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
bootroot init --enable auto-generate --responder-url http://localhost:8080
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
- Last successful AppRole `secret_id` rotation (when recorded in
  `state.json`), plus a dead-man **warning** when that timestamp is
  older than half the rotate roles' `secret_id` TTL (default `24h` →
  warns past `12h`) — the scheduled rotation job may have silently
  stopped. See
  [Operations > Dead-man monitoring and break-glass recovery](operations.md#dead-man-monitoring-and-break-glass-recovery).

### Failure conditions

The command is considered failed when:

- Missing/unhealthy containers
- OpenBao API unavailable

The dead-man warning does not fail the command; it is informational
output to act on.

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

- For `local-file`, start and keep the per-service OpenBao Agent sidecar and
  `bootroot-agent` running on the service machine; `bootroot service add`
  already prepares trust files on the same host so the first managed
  `bootroot-agent` run can start in verify mode
- For `remote-bootstrap`, edit the generated `remote run command template`,
  run `bootroot-remote bootstrap` once on the service machine, then keep
  `bootroot-agent` running. No OpenBao Agent sidecar runs on the remote host:
  the agent self-authenticates and pulls trust and `secret_id` rotations via
  fast-poll, so rotations propagate without a manual re-bootstrap or
  `apply-secret-id` (those are recovery paths only, for an agent offline past
  its `secret_id_ttl`)
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
- `--container-name`: docker container name (required for docker).
  Combining `--container-name` with `--deploy-type=daemon` is rejected;
  the flag has meaning only in docker mode.
- `--no-validate-agent`: skip the docker-mode identity check that
  confirms `--container-name` actually points at a bootroot-agent
  (label `bootroot.role=agent`, with a `bootroot-agent` substring
  fallback against image/entrypoint/cmd). Use when the agent container
  is not running yet at `service add` time, when `docker inspect` is
  unreachable, or for pre-existing deployments that lack the label.
  Scopes only to the docker identity check; does not bypass the
  daemon+`--container-name` reject above.
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

For the `sighup` preset, `--reload-target` must be a plain process
name (matched against `comm`, i.e. the basename of `argv[0]`;
Linux truncates `comm` to 15 characters). Path-like targets
containing `/` are rejected at `service add` time because the
preset invokes `pkill -HUP <name>` without `-f` and would
otherwise silently fail to match. For path-based matching, use
the low-level flags to opt into `pkill -f` explicitly:

```text
--post-renew-command pkill \
--post-renew-arg -HUP --post-renew-arg -f \
--post-renew-arg <your-path>
```

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

Cert/key group-access policy:

- `--cert-group <gid-or-name>`: numeric gid (or, for `local-file` only,
  group name) that should own the issued cert/key files and their
  parent directories.
  - Unset (default): the agent preserves the host-local default —
    `0700` parent directories, `0600` `<svc>-key.pem`, `0644`
    `<svc>-cert.pem`, owned by the operator's uid/primary gid.
  - Set: on every issuance and rotation the agent applies a
    group-readable policy — key parent `0750`, cert parent `0755`
    (or `0750` when the cert and key share a parent), key file
    `0640`, cert file `0644`, with both parent directories and both
    files group-owned by the configured gid. This is what makes the
    bind-mounted cert/key readable to a non-root containerized
    client without recurring operator `chmod` workarounds — the
    policy is reapplied on every renew, so it survives rotation.
  - The agent also writes `ca-bundle.pem` (when
    `[trust].ca_bundle_path` is configured) at `0644` on every
    issuance and rotation, and `chgrp`s it to the configured gid
    when the policy is active. `0644` is used regardless of policy
    because the bundle is public trust material (issuer/CA chain
    PEM only, never private keys); re-asserting the mode also
    overrides any stricter mode left behind by an earlier writer
    (e.g. `bootroot-remote bootstrap`'s `0600` secret-file write).
  - Mode-by-mode acceptance:
    - `local-file`: name or numeric gid. Names are resolved against
      the control host's group DB. `service add` and `service
      update` validate that the calling process can `chown` to the
      target gid (POSIX requires the caller to be a supplementary
      member of the group, or root); if not, the command fails at
      configure time rather than at the next rotation.
    - `remote-bootstrap`: numeric gid only. Names are rejected at
      parse time because the control host's NSS may diverge from
      the remote agent host's NSS. Operators must line up the same
      numeric gid on the control host, the cert-writing remote
      host, and the consuming container's supplementary group.
  - `--cert-group 0` (root) is rejected. The operator-only default
    already works for root; granting "the root group" would be a
    no-op against an obvious misconfiguration.
  - The numeric gid must also resolve in the **cert-writing host's**
    group database (`getgrgid_r`). An orphan gid — one that exists
    on a different host (e.g. the container image's runtime user)
    but not on the host that will actually `chown` the cert/key
    files — is rejected loudly. For `local-file` this check runs at
    `service add` / `service update` time on the control host
    (which is also the cert-writing host); for `remote-bootstrap`
    the same check runs on the remote agent host at
    `bootroot-remote bootstrap` time, and again at `bootroot-agent`
    config validation. Without this check the kernel would silently
    accept `chown(-1, gid)` and the consumer would still hit
    `EACCES` because the gid resolves to no real group.
  - When the policy is active, the cert parent directory is
    treated as a bootroot-owned cert output directory: mixing
    unrelated files into it is unsupported, since `0755` broadens
    traversal for whatever else lives there.

Persistence: `cert_group_gid` is stored on `ServiceEntry`, rendered
into the managed `agent.toml` profile block, threaded through the
remote-bootstrap artifact, and surfaced on `DaemonProfileSettings`,
so rotation always reapplies the same policy.

Atomicity: the key file is written via stage-then-rename — the bytes
are first written to a sibling temp file created with `O_CREAT|O_EXCL`
and `mode=0600`, the staged file is `chown`d and promoted to `0640`
(when the policy is active), and only then renamed over the
destination. The destination path is therefore never observable at a
mode wider than the final policy: there is no umask-derived `0644`
window before the clamp, and no group-readable window under the
operator's primary gid before the chown lands.

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
- `--container-name` combined with `--deploy-type=daemon`
- OpenBao AppRole creation failure

A non-fatal warning (registration still proceeds) is emitted when
`--deploy-type=docker` is used and the supplied `--container-name`
cannot be confirmed as a bootroot-agent: missing `bootroot.role=agent`
label, no `bootroot-agent` substring in image/entrypoint/cmd, or
`docker inspect` cannot be executed. Pass `--no-validate-agent` to
silence the warning when this is expected.

## bootroot service update

Modifies per-service `secret_id` policy fields, cert-group policy, and
post-renew hook configuration without re-running the full `service
add` flow. At least one update flag is required.

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
- `--cert-group <gid-or-name-or-clear>`: change the cert/key
  group-access policy on a previously added service. Accepts the
  same forms as `service add` (`local-file` accepts name or
  numeric; `remote-bootstrap` accepts numeric only), plus the
  literal string `clear` to remove an existing policy and revert
  to the operator-only default. For `local-file` services the
  command re-renders the managed `agent.toml` profile block in
  place so the next agent restart and the next rotation pick up
  the new policy. For `remote-bootstrap` services the command
  prints a warning instructing the operator to re-emit the
  bootstrap artifact (`bootroot service add`) and re-run
  `bootroot-remote bootstrap --artifact <path>` on the remote
  agent host so the new `cert_group_gid` lands in the remote
  `agent.toml`. See `service add` for the rationale and per-mode
  acceptance rules. The local-file re-render runs before
  `state.json` is saved, and re-runs of the same `--cert-group`
  value (even when it matches what is already in state) re-trigger
  the re-render — so a previously-failed re-render can be repaired
  by simply re-running the command, with no risk of state.json
  drifting ahead of the on-disk managed profile.
- `--reload-style`: reload style preset for the post-renew hook
  (`sighup`, `systemd`, `docker-restart`, or `none`). Same
  semantics as `service add`. Use `none` to clear a previously
  configured hook. Combine with `--reload-target` (process
  name, systemd unit, or container name) for the non-`none`
  presets. Mutually exclusive with the low-level
  `--post-renew-*` flags.
- `--reload-target`: target for the reload-style preset.
- `--post-renew-command`, `--post-renew-arg`,
  `--post-renew-timeout-secs`, `--post-renew-on-failure`:
  low-level hook configuration; same semantics as on
  `service add`.

For `local-file` services, a hook change re-renders the managed
`agent.toml` profile block in place. For `remote-bootstrap`
services, the command prints a warning instructing the operator
to re-emit the bootstrap artifact and re-run `bootroot-remote
bootstrap --artifact <path>` on the remote host so the updated
hooks land in the remote `agent.toml`. See [Operations →
Retrofitting a hook on an existing
service](operations.md#retrofitting-a-hook-on-an-existing-service)
for the rationale and the in-FD pitfall this guards against
(issue #614).

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
- No update flag provided

### Examples

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
bootroot service update --service-name edge-proxy --no-wrap
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit

# Retrofit a post-renew hook on an existing service (issue #614).
bootroot service update --service-name review \
  --reload-style sighup --reload-target review
bootroot service update --service-name aice-web-next \
  --reload-style docker-restart --reload-target aice-web-next
bootroot service update --service-name edge-proxy --reload-style none
```

## bootroot service remove

Deregisters a service and tears down its `OpenBao` material. This is the
supported way to change a registered service's `--delivery-mode` (e.g.
`local-file` → `remote-bootstrap`): remove the service, then re-add it
with the new mode. `service add` refuses to flip the delivery mode of an
existing entry (it bails with a duplicate-service error), so a
remove-then-re-add is the intended flow. Because changing delivery mode
regenerates the `secret_id` delivery material regardless, the fresh
`AppRole` `role_id` produced by re-adding is expected.

### Inputs

- `--service-name`: service name identifier (required)
- `--yes` (alias `--force`): skip the interactive confirmation prompt.
  Required for non-interactive use (CI / scripts); without it, and when
  stdin is not a terminal, the command refuses to proceed.
- `--dry-run`: print the teardown plan without mutating `state.json` or
  `OpenBao`.
- `--delete-artifacts`: also delete bootroot-owned on-disk artifacts —
  the cert/key files, the per-service secret and `OpenBao` config
  directories, and the remote-bootstrap artifact — and strip bootroot's
  managed profile block from `agent.toml`. **Off by default:**
  `service add` only records cert/key paths (the files are produced later
  by rotation / the agent), so on-disk material is preserved unless this
  flag is given. Even with the flag, `agent.toml` is edited in place —
  only the managed block is removed — so an operator-owned config file is
  never deleted.
- `--strip-config`: strip bootroot's managed profile block from
  `agent.toml` **without** deleting the cert/key files or the per-service
  secret and `OpenBao` config directories. Intended for a live
  delivery-mode transition, where the service is still serving so the
  cert/key must be kept, yet the stale managed block must go. Only the
  service's `[[profiles]]` entry and its marker comments are removed; the
  global `[trust]`, `[openbao]`, and `[acme]` tables the running agent
  depends on are preserved, even though they physically sit inside the
  marker comments. Implied by `--delete-artifacts` (combining the two is
  redundant but harmless). As with `--delete-artifacts`, the strip removes
  a block written under *either* delivery mode's markers, so a block left
  by the opposite mode (or by an older binary) is cleared regardless of
  which path wrote it.
- Runtime authentication flags (`--root-token`, `--root-token-file`,
  `--approle-role-id`/`--approle-secret-id`, `--auth-mode`, …): same as
  `service add`, used to authenticate to `OpenBao` for the teardown.

### Behavior

- Reads the service entry from `state.json` and prints the teardown
  plan: the `AppRole` and policy (by the names stored in state), the
  per-service KV paths, and — with `--delete-artifacts` — the on-disk
  files to delete.
- Performs remote cleanup first: deletes the per-service KV paths
  (`eab`, `http_responder_hmac`, the trust entry, and — for
  `remote-bootstrap` services — `secret_id`), the `AppRole`, and the
  policy. Each deletion tolerates an already-absent resource, so the
  command is safely re-runnable after a partial failure.
- Removes the `state.json` entry **last**, only after all remote (and,
  with `--delete-artifacts`, on-disk) teardown succeeds. A partial
  failure keeps the entry — and its stored role/policy names — so a
  re-run can finish the remaining deletions.
- Refreshes the `bootroot-http01` responder's HTTP-01 alias set so the
  removed service's alias is dropped, **including when the resulting
  alias set becomes empty** (removing the last alias-bearing service
  still reconnects the responder with only its base alias).

### Outputs

- Teardown plan
- Per-resource removed / already-absent lines
- Success confirmation, or — on partial failure — a report of which
  resources remain plus guidance to re-run

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- Service not found
- A remote or on-disk deletion fails (the `state.json` entry is kept for
  a re-run)

### Examples

```bash
# Preview the teardown plan.
bootroot service remove --service-name edge-proxy --dry-run

# Deregister a service (OpenBao AppRole/policy/KV torn down; cert/key
# and agent.toml preserved).
bootroot service remove --service-name edge-proxy --yes

# Change delivery-mode from local-file to remote-bootstrap. The re-add and
# subsequent bootstrap replace the stale managed block in place, so no
# manual agent.toml edit is needed; add --strip-config to the remove step
# to clear the block up front (keeping the cert/key) as a belt-and-braces
# step for a live transition.
bootroot service remove --service-name edge-proxy --yes --strip-config
bootroot service add --service-name edge-proxy \
  --delivery-mode remote-bootstrap ...

# Full teardown including on-disk artifacts and the managed agent.toml
# block.
bootroot service remove --service-name edge-proxy --yes --delete-artifacts
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

## bootroot service openbao-sidecar start

Starts the per-service **OpenBao Agent** (`bao agent`) sidecar
container for a registered service so secrets can be re-rendered
immediately on rotate. The command writes a per-service compose
override under
`secrets/openbao/services/<service>/docker-compose.override.yml` and
brings the sidecar up via `docker compose ... up -d`.

> Note: this command manages the **OpenBao Agent**, not the
> `bootroot-agent` certificate daemon. Two completely different
> binaries share the word "agent" — see
> [Naming disambiguation](#openbao-agent-vs-bootroot-agent) below.

### Inputs

- `--service-name`: service name identifier (must already exist in
  `state.json`)
- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--openbao-network`: docker network the sidecar should attach to
  (optional)
  - When omitted, the network is discovered from the
    `bootroot-openbao` container's `com.docker.compose.project` label
    as `<project>_default`.
  - Required when OpenBao runs **outside** bootroot's compose file
    (separate host, kubernetes, managed service, etc.) — there is no
    `bootroot-openbao` container to inspect, so an explicit network
    must be supplied.
  - Validated against the docker network naming rules
    (`^[A-Za-z0-9][A-Za-z0-9_.-]*$`) to prevent override-file
    injection.

### Behavior

The command resolves docker network and compose project according to
the following decision matrix (rows 1 and 2 read whether the compose
file declares an `openbao` service):

| OpenBao in compose | `--openbao-network` | Behavior |
| --- | --- | --- |
| present | unset | Discover project label on `bootroot-openbao`; use `<project>` for `-p` and `<project>_default` for the override network |
| present | set | Use the given network in the override; still discover project label for `-p` |
| absent | unset | Error: `--openbao-network` is required when OpenBao runs outside bootroot's compose |
| absent | set | Use the given network; omit `-p` (defaults to working-directory project) |

This replaces the previous behavior that hardcoded the compose
project to `bootroot` and the network to `bootroot_default`. As a
result, the command now works from any working directory and any
`COMPOSE_PROJECT_NAME` value without requiring a workaround such as
`COMPOSE_PROJECT_NAME=bootroot bootroot service openbao-sidecar start ...`.

The sidecar `up` is issued with `--no-deps`, so it brings up only the
sidecar and never reconciles or recreates the `bootroot-openbao`
container. Because the command resolves only the base
`docker-compose.yml`, a stack that publishes OpenBao through an
additional operator override (extra ports, networks, etc.) would
otherwise drift from the running container and get recreated —
re-sealing a shamir-sealed OpenBao and dropping the override-only
bindings. `--no-deps` avoids that regardless of which operator
override files published OpenBao.

### Outputs

- The created sidecar container is named
  `bootroot-openbao-agent-<service>`.
- Bind-mounts depend on the service's `--deploy-type`:
  - `daemon`: mounts the per-service config and cert directories at
    `/sidecar-config` and `/sidecar-certs` so the sidecar can render
    `agent.toml` and `ca-bundle.pem` directly at the paths
    `bootroot-agent` reads and `rotate` waits on.
  - `docker`: mounts only the shared secrets directory at
    `/openbao/secrets`.
- A success message in the form
  `bootroot service openbao-sidecar start: started bootroot-openbao-agent-<service>`.

### Prerequisites

- `bootroot infra install` and `bootroot service add` must have
  completed for the service.
- Then one of:
  - The compose file declares an `openbao:` service — the
    `bootroot-openbao` container must exist locally so the project
    label can be discovered. `--openbao-network` is optional in this
    branch and only overrides the network name; it does not bypass the
    label discovery.
  - The compose file does **not** declare an `openbao:` service
    (external-OpenBao case) — `--openbao-network` is required and is
    the only way to specify the sidecar's network. No container
    inspection is performed in this branch.

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- Service not found
- Service uses `--delivery-mode remote-bootstrap` (the local sidecar
  flow does not apply; secret_id handoff is operator-driven on the
  service machine)
- Per-service `agent-docker.hcl` config is missing
- The compose file declares an `openbao:` service but the
  `bootroot-openbao` container is not found (failure applies whether
  or not `--openbao-network` was supplied — the project label is still
  needed for `-p`)
- The compose file declares an `openbao:` service but the
  `bootroot-openbao` container exists without a
  `com.docker.compose.project` label
- The compose file does not declare an `openbao:` service and
  `--openbao-network` was not supplied
- `--openbao-network` (or the discovered network) fails the docker
  network name validation

### Examples

```bash
# Standard managed compose, any working directory.
bootroot service openbao-sidecar start --service-name edge-proxy

# External OpenBao (separate host / kubernetes / managed service).
bootroot service openbao-sidecar start \
  --service-name edge-proxy \
  --openbao-network app-shared-net

# Explicit network override even though OpenBao is in compose
# (e.g. attaching the sidecar to a non-default network).
bootroot service openbao-sidecar start \
  --service-name edge-proxy \
  --openbao-network ops-net
```

### OpenBao Agent vs `bootroot-agent`

`service openbao-sidecar start` runs the **OpenBao Agent** (`bao agent`), not
the `bootroot-agent` certificate daemon. Two completely different
software packages share the word "agent":

| Software | Role | Who runs it |
| --- | --- | --- |
| OpenBao Agent (`bao agent`) | Fetches secrets from OpenBao, renders templates | bootroot (sidecar) or operator (host daemon) |
| `bootroot-agent` | Issues/renews TLS certs against step-ca | Operator (host daemon, separate binary) |

`service openbao-sidecar start` only manages the first one.

### Sidecar vs. host-daemon for the OpenBao Agent

The two deployment models for the OpenBao Agent are independent of
the service `--deploy-type`. Even when the service runs as a host
daemon, the OpenBao Agent itself can run either as a
bootroot-managed sidecar container or as an operator-managed host
daemon (`bao agent
-config=secrets/openbao/services/<svc>/agent.hcl`).

| Concern | Sidecar (default) | Host daemon (alternative) |
| --- | --- | --- |
| rotate signal path | Active (`docker restart` → immediate re-render) | Passive (relies on `static_secret_render_interval = 30s` polling) |
| rotate latency | ~seconds | up to 30s |
| Lifecycle management | bootroot owns it (`service openbao-sidecar start`) | Operator owns it (systemd unit, etc.) |
| Container name | Standardized: `bootroot-openbao-agent-<svc>` | Operator's PID/unit naming |
| Privilege isolation | Token/secret_id contained in container | Mixed with host user permissions |
| Code path uniformity | Same pattern across docker/daemon deploy types | Only viable for daemon deploy type |
| Debugging | `docker logs bootroot-openbao-agent-<svc>` | `journalctl -u <unit>` (operator-defined) |

When the sidecar is **not** appropriate:

- Hosts without a docker engine.
- Security policies that mandate systemd-only lifecycles for
  token-handling processes.
- Highly resource-constrained environments where the sidecar
  overhead is unacceptable.
- Integration with HSMs / security modules accessible only outside
  containers.
- Pre-existing operator infrastructure standardized on systemd-based
  secret management.

**Recommendation:** sidecar is the default and recommended path.
`bootroot service add` already surfaces `bootroot service
openbao-sidecar start` as the primary next step. Choose the host-daemon alternative
only when one of the conditions above applies; in that case,
lifecycle management of the OpenBao Agent process becomes entirely
the operator's responsibility, and rotate latency increases to up to
`static_secret_render_interval` per rotate cycle.

## bootroot service openbao-sidecar refresh

Restarts the per-service `OpenBao` Agent sidecar so consul-template
re-reads its KV sources. Use after manual KV maintenance (clearing
stale EAB, rotating templated secrets, etc.) — consul-template caches
the previously-rendered value until the agent process restarts
(#588 §6).

### Inputs

- `--service-name`: service name identifier (must already exist in
  `state.json`)

### Behavior

- For services with `--delivery-mode local-file`: runs `docker
  restart bootroot-openbao-agent-<service-name>`.
- For services with `--delivery-mode remote-bootstrap`: emits
  operator guidance only (the sidecar lives on the remote host where
  bootroot has no signalling channel).

### Failure conditions

The command is considered failed when:

- Missing `state.json`
- Service not found
- `docker restart` fails (local-file delivery only)

### Examples

```bash
bootroot service openbao-sidecar refresh --service-name edge-proxy
```

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
- `--agent-binary`: path to the `bootroot-agent` binary (optional; when
  omitted, bootroot first tries the directory containing the running
  `bootroot` binary, then falls back to `$PATH`)
- `--db-check`: verify DB connectivity and auth using ca.json DSN
- `--db-timeout-secs`: DB connectivity timeout (seconds, default `2`)

### Interactive behavior

- Prompts for missing required inputs.
- Checks that inputs are not empty.
- Prints a plan summary before execution and the final summary after.

### Outputs

- cert/key presence
- CA bundle composition check (every fingerprint in
  `[trust].trusted_ca_sha256` is present in `[trust].ca_bundle_path`)
- verification summary
- DB connectivity check status (when enabled)

### Failure conditions

The command is considered failed when:

- bootroot-agent execution failure
- missing cert/key files
- `ca_bundle_path` is missing any fingerprint from
  `trusted_ca_sha256` (e.g. an intermediate-only post-issuance
  bundle that would break default TLS clients)

## bootroot rotate

Runs secret rotation workflows. It uses `state.json` to locate paths and
updates values through OpenBao.

Supported subcommands:

- `rotate stepca-password`
- `rotate db`
- `rotate responder-hmac`
- `rotate approle-secret-id`
- `rotate trust-sync`
- `rotate force-reissue`
- `rotate ca-key`
- `rotate openbao-recovery`
- `rotate eab-clear`
- `rotate infra-cert`

### Inputs

Common:

- `--state-file`: path to `state.json` (optional)
- `--compose-file`: compose file path (default `docker-compose.yml`)
- `--openbao-url`: OpenBao API URL (optional)
- `--kv-mount`: OpenBao KV mount path (optional)
- `--secrets-dir`: secrets directory (optional)
- `--auth-mode`: runtime auth mode (`auto`, `root`, `approle`, default `auto`)
- `--root-token`: OpenBao root token (CLI flag, transition/break-glass
  path). Mutually exclusive with `--root-token-file`.
- `--root-token-file`: path to a file containing the OpenBao root token.
  Resolution order is `--root-token-file` > `--root-token` >
  `OPENBAO_ROOT_TOKEN` env > interactive prompt. The file must not be
  world-readable; mode `0o644` is rejected with a `chmod 0600` hint.
  Group-readable (`0o640`) is permitted for shared CI/operator groups.
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
- `--yes` / `-y`: skip confirmation prompts. Accepted at any position
  under `rotate` (e.g. `rotate force-reissue --yes` or
  `rotate --yes force-reissue`).

Output behavior:

- By default, rotate subcommands mask secret-bearing stdout fields.
- Use `--show-secrets` only when plaintext stdout is intentionally required.
- This affects secret-bearing summary output such as root tokens and unseal
  keys.
- For `rotate openbao-recovery`, `--output` is separate from stdout masking:
  it writes plaintext credentials to the destination file while stdout prints
  only the summary and output path.

Per subcommand:

#### `rotate stepca-password`

- `--new-password`: new step-ca key password (optional, auto-generated if omitted)
- implementation note: bootroot runs `step crypto change-pass` with `-f`
  (`--force`) to avoid interactive overwrite prompts in non-interactive Docker
  environments.

#### `rotate db`

- `--db-admin-dsn`: DB admin DSN (env `BOOTROOT_DB_ADMIN_DSN`).
  Resolution order: this flag → `bootroot/stepca/db_admin` in
  OpenBao KV (written by `init --enable db-provision`, readable
  only by operator/root tokens). When neither is available the
  command fails with a message naming both sources. Pass the
  flag explicitly to override, or when running with an AppRole
  token whose policy excludes `db_admin`. `ca.json.db.dataSource`
  is **not** consulted: that field stores the runtime (`stepca`)
  DSN, and using it as an admin DSN was the original §2 self-ALTER
  bug. When the KV-backed path is used and the admin DSN's user
  matches the runtime user being rotated (the bundled same-role
  topology), `rotate db` also rewrites `bootroot/stepca/db_admin`
  with the new password after `provision_db_sync` completes, so
  subsequent rotations continue to authenticate. (#588 §2)
- `--db-password`: new DB password
  (optional, auto-generated if omitted, env `BOOTROOT_DB_PASSWORD`)
- `--db-timeout-secs`: DB timeout in seconds (default `2`)

#### `rotate responder-hmac`

- `--hmac`: new responder HMAC (optional, auto-generated if omitted)

#### `rotate approle-secret-id`

Rotates AppRole `secret_id`s — a single registered service, every
registered service at once, or one of the infra roles consumed by the
long-running OpenBao Agent sidecars. Exactly one of the three selectors
is required:

- `--service-name`: target service name. Authenticate with
  `bootroot-runtime-rotate-role` credentials.
- `--all-services`: rotates every service registered in `state.json`
  (both `local-file` and `remote-bootstrap` delivery modes) in one
  invocation. Authenticate with `bootroot-runtime-rotate-role`
  credentials. Designed for scheduled jobs (`--yes`): it continues past
  per-service failures, prints a per-target summary, and exits non-zero
  if any target failed; an empty service registry is a no-op success.
  Infra roles are deliberately excluded (separate credential — see
  below); schedule the two `--infra` invocations alongside it.
- `--infra <stepca|responder>`: target infra role
  (`bootroot-stepca-role` / `bootroot-responder-role`). Authenticate
  with `bootroot-infra-rotate-role` credentials via the usual
  `--auth-mode approle` flags.
- `--rotate-bound-cidrs`: CIDR ranges to bind the
  `bootroot-infra-rotate-role` credential to (repeatable). Only valid
  with `--infra` and only honored on the root-token provisioning run;
  the binding is recorded in `state.json` and applied to the minted
  operator credential and every subsequent self-mint. Omitted keeps
  the recorded binding (the run prints the binding it re-applied).
- `--clear-rotate-bound-cidrs`: removes the recorded
  `--rotate-bound-cidrs` binding and mints the operator credential
  unbound. Only valid with `--infra` and only honored on the
  root-token provisioning run; conflicts with `--rotate-bound-cidrs`.
  This is the recovery path for a recorded CIDR that locks the
  rotation job out — subsequent self-mints are unbound until a
  provisioning run records a new binding.

The two credentials are deliberately asymmetric: the runtime-rotate
credential can touch service AppRoles but not the infra roles (the
infra roles read CA core secrets, so minting their `secret_id`s would
be a privilege-escalation path), and the infra-rotate credential can
mint infra `secret_id`s but read nothing from KV. Each may re-mint
only its **own** `secret_id` — the self-mint that keeps the scheduled
rotation job from expiring itself.

Self-mint (mint-own-last): when the run authenticated as a rotate
AppRole and every target of the invocation succeeded, the command
re-mints the credential it authenticated with (`num_uses = 6`, the
recorded `--rotate-bound-cidrs` binding re-applied), verifies the new
`secret_id` with a login, and atomically replaces the file passed via
`--approle-secret-id-file`. Inline/env-supplied secret_ids have no
file to replace — the run warns and skips the self-mint. Root-token
runs never self-mint. Every successful invocation also records
`last_secret_id_rotation` in `state.json`, which `bootroot status`
watches as a dead-man signal. See
[Operations > The rotate credentials' own secret_ids (self-mint)](operations.md#the-rotate-credentials-own-secret_ids-self-mint).

For infra targets the command writes the new `secret_id` atomically
(mode `0600`) to `<secrets_dir>/openbao/<stepca|responder>/secret_id`,
backfills the sibling `role_id` file when missing, restarts the
matching `bootroot-openbao-agent-stepca` /
`bootroot-openbao-agent-responder` container so the sidecar
re-authenticates, and verifies the new credential with an AppRole
login (infra roles carry no CIDR binding, so the check always runs).

Upgrade path: deployments initialized before `bootroot-infra-rotate-role`
existed do not have the role or its policy. Running an `--infra`
rotation once with the root token (`--auth-mode root` or
`--root-token(-file)`) provisions both, records them in `state.json`,
and prints the new role's `role_id` and `secret_id` (masked unless
`--show-secrets`) so day-2 rotations can switch to the scoped
credential. The provisioning run preserves the `secret_id` TTL
recorded at `init --secret-id-ttl` instead of resetting the role to
the default, so the live credential's lifetime keeps matching the
threshold `bootroot status` derives from `state.json`. With AppRole
credentials the command never attempts provisioning; a missing role
surfaces as a permission error with a hint.

#### `rotate trust-sync`

Syncs CA certificate fingerprints and bundle PEM to OpenBao and updates
each service's trust data. For remote services, the trust payload is
written to per-service KV paths. For local services, the agent config
`[trust]` section is updated and the CA bundle PEM is written to disk.

No additional arguments.

#### `rotate force-reissue`

Triggers an immediate certificate reissue for a service.

For local (daemon) and Docker services, deletes the recorded cert/key
files and sends SIGHUP / restarts the container so bootroot-agent reissues
on the next loop tick.

For `--delivery-mode remote-bootstrap` services, the control plane has no
push channel into the remote host, so cert files cannot be deleted
remotely. Instead the command writes a versioned reissue request to
`{kv_mount}/data/bootroot/services/<service>/reissue` in OpenBao with
`requested_at` and `requester` fields. The remote bootroot-agent requires
the `[openbao]` section in its `agent.toml` — `bootroot-remote bootstrap`
auto-provisions it on every run — and polls this path on its
`fast_poll_interval` (default 30s). When it observes a KV v2 version
newer than the one it last applied it triggers an immediate ACME
renewal, and after success writes back `completed_at` and
`completed_version` so the control plane can observe end-to-end latency.

Inputs:

- `--service-name`: target service name
- `--requester`: optional operator label written to the reissue KV
  payload for observability. Defaults to `$USER` / `$LOGNAME`, or
  `unknown` when neither is set.
- `--wait`: blocks until bootroot-agent reports completion (or the
  timeout expires). For `--delivery-mode remote-bootstrap` services it
  polls `completed_at` on the KV reissue path; for local-file services
  it polls the on-disk cert at `paths.cert` until the serial changes
  (mtime is used only as a tiebreaker for the rare same-serial reissue
  case). On success the summary line also reports the end-to-end
  latency (for remote, `completed_at - requested_at` from the KV
  payload; for local, the wall clock between the signal and the cert
  rewrite) in a human-readable form so the operator does not need to
  subtract timestamps manually.
- `--wait-timeout`: maximum time to wait when `--wait` is set. Accepts
  humantime durations (e.g. `90s`, `2m`). Default `2m`.

Without `--wait` the command returns immediately after the KV write
(remote) or the SIGHUP/restart signal (local); bootroot-agent will apply
the reissue within ~one poll interval of its next tick. A `--wait`
timeout is not an error: the request stays queued and the agent still
picks it up on its next poll.

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
  fingerprints, with a `ca-bundle.pem` carrying both CA generations) to
  OpenBao so services accept both old and new certificates and
  `bootroot verify` passes while the rotation is in flight
- Phase 4 — Restart step-ca: restart the step-ca container so it uses the
  new key pair
- Phase 5 — Re-issue: delete service cert/key files and signal
  bootroot-agent (SIGHUP for daemon, container restart for Docker) to
  trigger re-issuance with the new CA. Remote-bootstrap services publish
  a versioned reissue request to OpenBao KV instead; remote agents pick
  it up on their fast-poll interval (see `rotate force-reissue`)
- Phase 6 — Finalize trust: write final trust (new fingerprints only) to
  OpenBao, removing old fingerprints, then restart the per-service
  OpenBao Agent sidecars so local `agent.toml` trust pins and
  `ca-bundle.pem` re-render immediately instead of waiting out the
  static-secret render interval
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

- `--rotate-unseal-keys`: rotate unseal keys via the authenticated
  root-key rotation API (`sys/rotate/root`)
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

#### `rotate eab-clear`

Clears EAB credentials from every known KV path so the next
bootroot-agent cycle does not template stale or invalid EAB material
into `agent.toml`. Companion to the now-removed `rotate eab` and the
recovery path for the symptom closed by `--no-eab` and the EAB
input validator (#588 §3c).

Behavior:

- Writes empty `{kid: "", hmac: ""}` to `bootroot/agent/eab` and to
  every per-service path `bootroot/services/<svc>/eab` enumerated
  from `state.json` (not from KV listings).
- After each write, refreshes the affected sidecar via the same
  branch as `service openbao-sidecar refresh`: `LocalFile` services
  receive `docker restart bootroot-openbao-agent-<svc>`;
  `RemoteBootstrap` services emit operator guidance only.
- `LocalFile` refresh failures are collected, not swallowed: every
  service is still attempted (so no service is left with stale KV),
  but if any sidecar refresh fails the command exits non-zero and
  names the affected services so the operator does not silently
  leave the §6 stale-render symptom in place.
- After completion, consul-template renders the
  `{{ if .Data.data.kid }}...{{ end }}` branch as empty and
  `agent.toml` no longer carries an `[eab]` block on the next cycle.

No additional arguments. Honors the global `--yes` to skip the
confirmation prompt.

#### `rotate infra-cert`

Renews infrastructure TLS certificates registered in `state.json` →
`infra_certs`. Today this covers the **OpenBao server TLS** cert
(`openbao` entry) and, when the HTTP-01 responder admin API was
provisioned with TLS, the **HTTP-01 admin TLS** cert
(`bootroot-http01` entry). The set is data-driven from
`infra_certs`; the loop body does not change when a new entry type
is added — only the per-key dispatch arm.

No subcommand-specific arguments. Honors the global `--yes` to skip
the confirmation prompt. The command accepts the common `bootroot
rotate` flag surface, but short-circuits before any OpenBao
interaction, so only `--state-file`, `--compose-file`,
`--secrets-dir`, and `--yes` actually influence behavior. The
OpenBao auth flags (`--auth-mode`, `--root-token` /
`--root-token-file`, `--approle-*`), the OpenBao connection flags
(`--openbao-url`, `--kv-mount`), and `--show-secrets` are accepted
but unused.

Behavior:

- Iterates every entry in `state.json` → `infra_certs`. From each
  entry the reissue path consumes `sans` (to reproduce the SANs of
  the original cert) and `reload_strategy` (to refresh the affected
  container after the write). The `cert_path` / `key_path` /
  `renew_before` / `expires_at` fields recorded in the entry are
  informational only — they are not consulted to decide where the
  renewed material is written.
- Per-entry reissue dispatch — the output paths are fixed by the
  dispatched function, not by the entry's `cert_path` / `key_path`:
  - `openbao` → re-issues the OpenBao server cert and writes it to
    `<compose-dir>/openbao/tls/server.crt` and
    `<compose-dir>/openbao/tls/server.key`. Both files are then
    `chmod 0644`'d so the in-container `openbao` user (which is in
    neither the runner's primary group nor any shared group) can
    read them via the "other" permission bits.
  - `bootroot-http01` → re-issues the HTTP-01 responder admin API
    cert and writes it to
    `<secrets-dir>/bootroot-http01/tls/server.crt` and
    `<secrets-dir>/bootroot-http01/tls/server.key`. Both files are
    `chmod 0600`'d after write.
- After each successful reissue the entry's `issued_at` is
  refreshed and the entry's `reload_strategy` runs so the affected
  container picks up the new material:
  - `ContainerRestart` (OpenBao) → `docker restart <container>`.
  - `ContainerSignal` (HTTP-01 admin) → `docker kill -s SIGHUP
    <container>`.
- Once every entry has been processed, the updated `infra_certs`
  map is persisted back to `state.json`.

No-op condition:

- When `infra_certs` is empty, the command prints a "no entries"
  message and exits 0 without prompting.

Failure conditions:

- Missing `state.json` — the common rotate path bails before
  subcommand dispatch.
- Local CA signing failure during a per-entry reissue. Both
  dispatch arms run `docker ... step certificate create` against
  the local step-ca intermediate (`--ca`, `--ca-key`,
  `--ca-password-file`); this is **not** ACME. Surfaces as a
  failure of the `step certificate create` docker invocation
  (e.g. step-ca image missing, intermediate cert/key path
  unreadable, password file mismatch).
- File-write or permission failure on the fixed output paths
  listed above (write of the renewed cert/key, or the subsequent
  `chmod` step).
- Reload-step failure (target container not running, signal
  delivery failure, etc.). The reissue dispatch is wrapped with
  the affected entry name, so a failure during the issue/write
  phase identifies the entry; the subsequent reload step is not
  wrapped with the entry name, so a reload failure identifies
  only the affected container and signal/restart operation. In
  either case the operator can re-run after fixing the
  underlying cause.

Examples:

```bash
bootroot rotate infra-cert
bootroot rotate infra-cert --yes
```

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
- responder config write fails or reload fails
- OpenBao recovery unseal-key/root-token rotation fails
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

  `cert-duration` must be strictly greater than the daemon's default
  `renew_before` (16h); otherwise every newly issued certificate is
  flagged for immediate renewal and the command fails validation. This
  is the same conservative guardrail `bootroot init` applies. The
  control plane does not read `agent.toml`, so per-agent
  `renew_before` consistency remains the operator's responsibility.

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
- `--openbao-only`: remove only the `bootroot-openbao` container and
  its volume; leave `bootroot-postgres`, `bootroot-http01`,
  `bootroot-ca`, `secrets/`, `state.json`, and `.env` intact. Useful
  when only the OpenBao state is fouled (e.g. after a partial-init
  failure — see #588 §5).

### Behavior

- Runs `docker compose down -v --remove-orphans`
- Removes `secrets/`, `state.json`, `.env`, and optionally `certs/`
- Prompts for confirmation before destructive actions (unless `--yes`)
- With `--openbao-only`: only the `openbao` compose service is
  stopped, removed, and its volume dropped. Other services keep
  running and on-disk state is preserved.

### Examples

```bash
bootroot clean
```

Recover from a partial-init OpenBao state without losing application
DB or step-ca state:

```bash
bootroot clean --openbao-only --yes
```

## bootroot reinit

Atomically recovers from a partial-init OpenBao state by wiping
OpenBao-owned state, re-bringing OpenBao up via the existing
`infra up` path, and re-running the standard init flow in
**reinit mode** (step-ca CA material and `password.txt` are
preserved, recorded non-loopback bind intent is preserved, and
already-preserved files do not trigger overwrite prompts).

Use `reinit` instead of `init` whenever:

- A previous `bootroot init` failed after OpenBao was initialised but
  before a usable root token was saved (the “partial-init” trap).
- A work directory was copied to another host via `rsync` and the
  destination's stale `state.json` is fighting with the new host's
  fresh OpenBao volume.
- An operator already ran `bootroot clean --openbao-only` and is now
  stuck because subsequent `bootroot init` cannot reach a running
  OpenBao.

`reinit` only operates on **compose-managed local OpenBao**.
External or shared OpenBao instances are rejected; use an
operator-managed runbook for those.

### Inputs

- `--openbao-url`: must be left at the CLI default
  (`http://localhost:8200`). Any other value is rejected before any
  destructive operation begins because `reinit` only operates on
  compose-managed local OpenBao; honouring an arbitrary URL would
  let `reinit` wipe local state and then operate on an external
  endpoint. Legitimate non-loopback recovery does not need this
  flag — the init pass URL is derived automatically from the
  snapshotted `openbao_bind_addr`.
- `--kv-mount`: KV mount path (default `secret`)
- `--secrets-dir`: secrets directory (default `secrets`)
- `--compose-file`: docker-compose.yml path (default
  `docker-compose.yml`)
- `--yes` / `-y`: skip confirmation prompts; non-interactive,
  newly generated unseal keys are written automatically to
  `secrets/openbao/unseal-keys.txt` (mode `0600`)
- `--root-token-output <path>` *(opt-in)*: write the freshly issued
  root token to `<path>` with restricted permissions (`0600`). This
  is intended for dev/test or ephemeral automation only — persistent
  root token files are **not recommended for production**. When the
  destination already exists with world-/group-readable permissions,
  reinit refuses to overwrite it. The path is preflight-checked
  before any destructive operation: reinit refuses to start if the
  path is a directory, if the existing file is not writable by the
  current process (e.g. mode `0400`), or if the parent directory
  cannot accept a new file, so a bad path cannot leave the operator
  with a wiped-and-reinitialised OpenBao plus a failed token write.
  New token files are created atomically with mode `0600` via
  `OpenOptionsExt::mode` so the freshly minted root token is never
  observable on disk with the process umask's default permissions
  between create and chmod. Should the post-init write still fail
  (e.g. disk full), the freshly issued token is surfaced on stderr in
  cleartext (prefixed with `ROOT_TOKEN=`) so it is not lost.
- `--enable <features>`: passed through to `init` (e.g.
  `show-secrets`). `db-provision` is accepted but becomes a no-op
  when reinit finds a preserved `secrets/config/ca.json` runtime DSN:
  that DSN is authoritative (the PostgreSQL role's password was
  rotated to it on the previous init), so re-running provisioning
  would `ALTER ROLE` the already-good credential to whatever
  `db-provision` synthesised and break the next rotate cycle. The
  preserved DSN is threaded into the second init pass and flows back
  into the freshly reinitialised OpenBao KV verbatim. When `ca.json`
  is absent (rsync-clone path or a partial-init that crashed before
  `update_ca_json_with_backup` ran), `db-provision` behaves as in
  `init`.
- `--skip <phases>`: passed through to `init` (e.g.
  `responder-check`)
- `--summary-json <path>`: passed through to `init`. The path is
  preflight-checked before any destructive operation: reinit refuses
  to start if the path is a directory, an unwritable existing file,
  an existing file with world-/group-readable permissions (mode
  `0o644` etc. is rejected with a `chmod 0600` hint), or has an
  unwritable / uncreatable parent. The summary JSON carries the
  freshly issued root token and unseal keys, so an unwritable
  destination would recreate the partial-init trap through a
  different output channel, and a wider-than-`0600` destination
  would briefly leak those secrets on disk between the write and
  the post-write chmod. The summary file itself is written
  atomically: new files are born `0600` via the create-mode flag,
  and any existing destination is tightened to `0600` before the
  secret payload is written, so the JSON never lands on disk with
  wider permissions.
- `--no-eab`: passed through to `init`

### Behavior

- Refuses to run when the compose file does not declare an
  `openbao` service, or when an existing `bootroot-openbao`
  container's compose labels do not match the project derived from
  the current work directory. A container that exists but is missing
  either compose label (`com.docker.compose.project`,
  `com.docker.compose.service`) is also rejected — it cannot be
  proven to belong to this work directory's compose project, and
  must not be collapsed into the stuck-after-`clean --openbao-only`
  recovery path.
- Snapshots deployment-intent fields from `state.json` (OpenBao /
  HTTP-01 admin bind/advertise addresses, `infra_certs`, `secrets_dir`)
  before any destructive operation.
- When the snapshot records a non-default `secrets_dir` (e.g. the
  previous init ran with `--secrets-dir secrets-custom`), the
  snapshot wins over the CLI default and drives **all** secrets-tree
  operations: artifact cleanup, the preserved `ca.json` DSN read, the
  preserved `password.txt` lookup, the second init pass's
  `--secrets-dir`, and the rewritten `state.json.secrets_dir`.
  Operators do not need to re-pass `--secrets-dir` on the reinit
  invocation when recovering a previously initialised deployment.
- Prints a plan listing every destructive action, every preserved
  artifact, and the snapshotted intent fields (effective
  `secrets_dir`, OpenBao bind/advertise, HTTP-01 admin
  bind/advertise, `infra_certs` count) so the operator can verify the
  recovery target before confirming. Without `--yes`, prompts for
  confirmation.
- Stops and removes the `bootroot-openbao` container and the
  `openbao-data` / `openbao-audit` volumes (the project's other named
  volumes — `postgres-data`, `prometheus-data`, `grafana-data` — are
  not touched).
- Removes only OpenBao runtime/bootstrap artifacts:
  `secrets/openbao/unseal-keys.txt`, generated OpenBao Agent
  config trees under `secrets/openbao/{stepca,responder,services}`,
  `secrets/openbao/docker-compose.openbao-agent.override.yml`, and
  stale per-service AppRole credential files
  (`secrets/services/<svc>/{role_id,secret_id,secret_id.wrapped}`).
- Preserves step-ca material (`secrets/config/ca.json`,
  `secrets/secrets/root_ca_key`, `secrets/secrets/intermediate_ca_key`),
  `secrets/password.txt`, the PostgreSQL container/volume, and
  operator-authored compose overrides under `secrets/openbao/`.
- Rewrites `state.json` with deployment intent only — service
  registry, AppRoles, and policies are intentionally empty.
- Brings OpenBao back up via `infra up --services openbao` so any
  recorded non-loopback bind override is layered correctly.
- When the snapshotted `openbao_bind_addr` is non-loopback, the
  second `init` pass targets the restored bind address
  (`https://<bind>`) instead of `http://localhost:8200` so the
  post-up health check reaches the TLS-enabled OpenBao without
  requiring the operator to re-pass `--openbao-url` manually. The
  CLI rejects any explicit `--openbao-url` value to prevent reinit
  from operating on an external endpoint, so this snapshot-driven
  rewrite is the only sanctioned channel for non-loopback init-pass
  URLs.
- Re-runs `init` in reinit mode (preserves the existing step-ca
  password when `secrets/password.txt` is present, suppresses
  overwrite prompts for preserved files, auto-generates the new
  HTTP-01 responder HMAC because the previous one lived in the wiped
  OpenBao KV mount, and skips the EAB registration prompt —
  operators who need EAB credentials register them out of band after
  reinit). When `secrets/password.txt` is absent (rsync-clone path
  or operator-removed) **and** every file `step ca init` writes is
  also absent — `secrets/config/ca.json`,
  `secrets/config/defaults.json`, `secrets/certs/root_ca.crt`,
  `secrets/certs/intermediate_ca.crt`,
  `secrets/secrets/root_ca_key`,
  `secrets/secrets/intermediate_ca_key` — the step-ca password is
  auto-generated non-interactively so `reinit --yes` never stalls on
  a password prompt; the new password is written to
  `secrets/password.txt` and encrypts the freshly initialised CA
  material that the second init pass creates from scratch. When
  `secrets/password.txt` is absent **but any preserved step-ca
  artifact is still on disk** — any of the six paths listed above —
  reinit refuses to start before any destructive operation runs.
  Encrypted CA keys (`root_ca_key` / `intermediate_ca_key`) are
  blocking because they were encrypted with the original password,
  so generating a fresh one would render a deployment whose
  `password.txt` cannot unlock the preserved CA keys, and any later
  `step certificate create --ca-password-file /home/step/password.txt`
  path (OpenBao / HTTP-01 TLS issuance) would fail. Any other
  preserved file `step ca init` writes (`config/ca.json`,
  `config/defaults.json`, `certs/root_ca.crt`,
  `certs/intermediate_ca.crt`) is equally blocking even without
  encrypted key material, because the second init pass's
  `step ca init` cannot complete cleanly when one of its targets
  already exists (it generates fresh cert/key files and then exits
  non-zero on TTY-bound overwrite confirmation), recreating the
  partial-init trap after OpenBao has already been wiped. Restore
  `password.txt` from a backup, or remove every preserved step-ca
  artifact to opt into a clean CA rebuild, then retry.
- Reads the preserved step-ca runtime DSN from
  `secrets/config/ca.json` and seeds the second init pass with it so
  the freshly reinitialised OpenBao KV receives credentials that
  still match the preserved PostgreSQL state. After a previous
  `init --enable db-provision` run, `.env`'s `POSTGRES_PASSWORD` has
  been rotated to a dummy `rotated-use-openbao` sentinel and only
  `ca.json` carries the real runtime password; without this seeding,
  the env-derived dummy DSN would land in OpenBao KV and step-ca
  agents would be pointed at credentials that no longer authenticate.
  When `ca.json` is absent (rsync-clone path or a partial-init that
  crashed before `update_ca_json_with_backup` ran), reinit falls
  through to the env-derived resolver — `.env` carries the real
  password in those scenarios.
- Also derives the ACME provisioner name and `defaultTLSCertDuration`
  from the preserved `ca.json`. Deployments initialised with
  `bootroot init --stepca-provisioner <custom>` keep that name on the
  second init pass (otherwise `update_ca_json_with_backup`'s
  lookup-by-name path would bail with
  `ca.json does not contain an ACME provisioner named "acme"` after
  OpenBao has already been wiped), and deployments initialised with a
  non-default `--cert-duration` keep that value (otherwise the value
  would be silently snapped back to the default on every reinit).
  When `ca.json` is absent or has no ACME provisioner, the CLI
  defaults apply as a fallback.
- After reinit, the service registry is empty — re-run
  `bootroot service add ...` for each service that was previously
  registered.

### Examples

Recover from a partial-init OpenBao state non-interactively:

```bash
bootroot reinit --yes
```

Recover and capture the freshly issued root token for ephemeral
automation (dev/test only — not recommended for production):

```bash
bootroot reinit --yes --root-token-output ./.root.token
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
updates local files such as `agent.toml`. After the initial bootstrap, the
running `bootroot-agent` keeps trust and `secret_id` current via its
fast-poll loop; `bootroot-remote apply-secret-id` is a recovery path for an
agent that was offline past its `secret_id_ttl`.
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
    values are baked into the artifact, not passed on the command line. Pass
    `--agent-email`, `--agent-server`, and `--agent-responder-url` to
    `bootroot service add` (under both `--delivery-mode local-file` and
    `--delivery-mode remote-bootstrap`) to bake non-default topology values
    into the artifact at service-add time. If those flags are omitted the
    localhost compose defaults are used, which are only correct for same-host
    setups; on a separate service machine, either supply the overrides at
    service-add time or edit `bootstrap.json` to replace them with
    remote-reachable endpoints (e.g., `stepca.internal`, `responder.internal`)
    before transferring the artifact.
  - Under `--delivery-mode remote-bootstrap`, the resolved
    `--agent-email` / `--agent-server` / `--agent-responder-url` values
    are persisted on the service entry in `state.json`. An idempotent
    rerun of `bootroot service add` (same service name, same other
    flags) regenerates `bootstrap.json` from the stored values — you do
    not have to restate the flags each time. If you rerun with a
    different value in any of those three flags, the rerun is rejected
    as a duplicate rather than silently flipping the generated artifact
    away from the stored definition; remove and re-add the service to
    change topology.
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

If `agent.toml` already exists on the remote target but is missing
baseline keys (for example `email`, `server`, or
`[acme].http_responder_url`), bootstrap backfills those keys without
clobbering operator-customised values. When the artifact carries
explicit `--agent-email` / `--agent-server` / `--agent-responder-url`
overrides (propagated from the upstream `bootroot service add`), those
values are then upserted over any pre-existing values in the file so
the KV re-render loop stops reverting the operator's intended ACME
topology to bootroot-agent's compiled-in defaults.

### `bootroot-remote apply-secret-id`

Applies a rotated secret_id to the remote service machine. This is a
**recovery** path, not the steady state: a running `bootroot-agent` already
pulls rotated secret_ids from OpenBao via its fast-poll loop. Use this
command only to recover an agent that was offline past its `secret_id_ttl`
(its credential already expired, so it can no longer self-refresh).

Key inputs:

- `--openbao-url`: OpenBao API URL (environment variable: `OPENBAO_URL`)
- `--kv-mount`: OpenBao KV v2 mount path
  (environment variable: `OPENBAO_KV_MOUNT`)
  (default `secret`)
- `--service-name`
  - Must follow the same single-label DNS rule as `bootroot service add`
- `--role-id-path`, `--secret-id-path`
- `--ca-bundle-path`: PEM CA bundle that anchors TLS when `--openbao-url` is
  `https://`. Point it at the same CA file `bootroot-remote bootstrap` wrote
  (the agent's `[openbao].ca_bundle_path`). Required for HTTPS — without it the
  AppRole login fails fast with a clear error; ignored for `http://`.
- `--output text|json` (default `text`)

Output safety semantics:

- text output redacts per-item error details
- JSON output is machine-readable and should be treated as sensitive artifact
