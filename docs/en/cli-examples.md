# CLI Examples

This section walks through a **production-like flow** using the `bootroot`
CLI. Outputs include as much of the CLI result as possible, and your
environment may differ.

## Prerequisites

- Docker/Docker Compose installed
- Ports 80/443/8200/9000/5433/8080 available (host-side `PostgreSQL`
  publishes on 5433 by default; override with `POSTGRES_HOST_PORT` or
  `bootroot infra install --postgres-host-port <N>`)

The Docker daemon should be configured to **start on reboot**. bootroot's
containers use restart policies, but Docker itself must be managed by the OS
(for example, via systemctl).

> Note: The example assumes OpenBao/PostgreSQL/HTTP-01 responder run on the
> **same machine as step-ca**.

## 1) infra install

```bash
bootroot infra install
```

This is the first command to run on a fresh clone. It generates `.env` with a
random PostgreSQL password, creates `secrets/` and `certs/` directories,
pulls/builds images, and starts Docker Compose services. No manual environment
variable setup or image prep is needed.

Sample output:

```text
bootroot infra up: readiness summary
- openbao: running (health: healthy)
- postgres: running (health: healthy)
- bootroot-http01: running (health: healthy)
- step-ca: not checked (will be bootstrapped by init)
bootroot infra install: completed
```

To restart an already-configured environment later, use `bootroot infra up`
instead.

## 2) init

> Minimum input summary:
>
> - If OpenBao is **not initialized**, initialize it first and use the
>   generated `root token` and `unseal keys`
> - If OpenBao is **initialized but sealed**, you need `unseal keys`
> - After `bootroot infra install`, DB credentials come from `.env`
>   automatically — use `--enable db-provision` to auto-provision the
>   PostgreSQL role and database (no manual `--db-dsn` needed)
> - step-ca password can be auto-generated with `--enable auto-generate`
> - `--responder-url` enables responder validation (otherwise skipped)
> - step-ca bootstrap (`step ca init`) runs automatically inside `init`

```bash
bootroot init --enable auto-generate,db-provision \
  --summary-json ./tmp/init-summary.json \
  --responder-url "http://localhost:8080"
```

Sample dialog/output (full):

```text
OpenBao root token: ********
OpenBao unseal key (comma-separated): key-1,key-2,key-3
Overwrite password.txt? [y/N]: y
Overwrite ca.json? [y/N]: y
Proceed with init? [y/N]: y

bootroot init: summary
- OpenBao URL: http://localhost:8200
- KV mount: secret
- Secrets dir: secrets
- OpenBao init: completed (shares=5, threshold=3)
- root token: ********
- unseal key 1: ********
- unseal key 2: ********
- unseal key 3: ********
- step-ca password: ********
- db dsn: ********
- db provision: completed
- responder hmac: ********
- eab: not configured
- step-ca init: completed
- responder check: ok
- db host resolution: localhost -> postgres
- OpenBao KV paths:
  - bootroot/stepca/password
  - bootroot/stepca/db
  - bootroot/http01/hmac
  - bootroot/ca
  - bootroot/agent/eab
- summary json: ./tmp/init-summary.json
Save unseal keys to file for automatic unseal? [y/N]: y
next steps:
  - Attach AppRole/secret_id to the service.
  - Prepare OpenBao Agent/bootroot-agent execution.
```

For automation, read sensitive fields (for example root token) from
`./tmp/init-summary.json` instead of parsing human-readable text output.

## 3) service add

`--delivery-mode` in `bootroot service add` selects how service configuration is
applied.

- default: `local-file`
- `local-file`: use when the service is added on the **same machine** as
  step-ca/OpenBao/responder
- `remote-bootstrap`: use when the service is added on a **different machine**
  from step-ca/OpenBao/responder
- `--dry-run`, `--print-only`: both run in preview mode and do not write files
  or state.
- To show trust snippets in preview, also provide `--root-token`.
- If preview runs without `--root-token`, the CLI prints why trust snippets are
  unavailable.

Sections 3-1 and 3-2 below are default (`local-file`) examples, and 3-3 is a
`remote-bootstrap` example.

> Note: `secrets/...` paths in sample outputs assume the default
> `--secrets-dir secrets`. If you use another secrets root in production
> (for example `/etc/bootroot/secrets`), read them with the same relative
> structure.

### 3-1) local-file (default)

```bash
bootroot service add \
  --service-name edge-proxy \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config /etc/bootroot/agent.toml \
  --cert-path /etc/bootroot/certs/edge-proxy.crt \
  --key-path /etc/bootroot/certs/edge-proxy.key \
  --instance-id 001 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

Sample dialog/output (abridged):

```text
OpenBao root token: ********

bootroot service add: summary
- service name: edge-proxy
- hostname: edge-node-01
- domain: trusted.domain
- delivery mode: local-file
- policy: bootroot-service-edge-proxy
- AppRole: bootroot-service-edge-proxy
- role_id: ********
- secret_id path: secrets/services/edge-proxy/secret_id
- OpenBao path: bootroot/services/edge-proxy
Bootroot-managed:
- auto-applied bootroot-agent config: /etc/bootroot/agent.toml
- auto-provisioned EAB file (present only when EAB is configured; pass
  its path via --eab-file): secrets/services/edge-proxy/eab.json
next steps:
Operator-managed (required):
  - Add profile for edge-proxy (instance_id=001, hostname=edge-node-01,
    domain=trusted.domain, cert=/etc/bootroot/certs/edge-proxy.crt,
    key=/etc/bootroot/certs/edge-proxy.key) to /etc/bootroot/agent.toml
    and reload bootroot-agent.
daemon profile snippet:
[[profiles]]
service_name = "edge-proxy"
...
daemon run command (systemd ExecStart or shell; --eab-file is required
for EAB rotation to apply):
bootroot-agent --config /etc/bootroot/agent.toml \
  --eab-file secrets/services/edge-proxy/eab.json
```

The generated `agent.toml` is a complete, ready-to-run config: it includes
the managed profile, `[trust]` section, top-level `domain` (from `--domain`),
`[acme].http_responder_hmac` (from the responder HMAC stored in OpenBao),
and the `[openbao]` section that activates the agent's fast-poll self-auth
loop (with an absolute service-keyed `state_path` next to `agent.toml`).
The HTTP-01 validation FQDN is also registered as a DNS alias on
`bootroot-http01` automatically.
No manual editing is required before running `bootroot-agent`; run it as a
host daemon with the printed run command (keep `--eab-file`).

### 3-2) local-file: containerized consumer application

The bootroot-agent itself still runs as a host daemon. For an application
that runs in a container, point `--cert-path`/`--key-path` at a host
directory the container bind-mounts, and configure a `docker-restart`
post-renew hook with the explicit container name:

```bash
bootroot service add \
  --service-name web-app \
  --hostname web-01 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /opt/web-app-mtls/web-app.crt \
  --key-path /opt/web-app-mtls/web-app.key \
  --instance-id 001 \
  --reload-style docker-restart \
  --reload-target web-app \
  --root-token <OPENBAO_ROOT_TOKEN>
```

See
[Operations > Containerized consumer applications](operations.md#containerized-consumer-applications)
for the bind-mount pattern and the hardened-unit/Docker-socket trade-off.

### 3-3) remote-bootstrap delivery mode + one-shot bootstrap

For a full operator guide including transport options, `secret_id` hygiene,
and the artifact schema reference, see
[Remote Bootstrap Operator Guide](remote-bootstrap.md).

Control node onboarding (artifact generation):

```bash
bootroot service add \
  --service-name edge-remote \
  --delivery-mode remote-bootstrap \
  --hostname edge-node-02 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /srv/bootroot/certs/edge-remote.crt \
  --key-path /srv/bootroot/certs/edge-remote.key \
  --instance-id 101 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

Remote node one-shot bootstrap (recommended `--artifact` invocation):

```bash
bootroot-remote bootstrap \
  --artifact /srv/bootroot/secrets/services/edge-remote/bootstrap.json \
  --output json
```

When wrapping is enabled (the default), the artifact carries a
`wrap_token` that `bootroot-remote` unwraps at runtime to obtain
`secret_id`. This avoids exposing sensitive tokens in shell command
lines and `ps` output. The per-field CLI flag style shown below still
works for backward compatibility or when wrapping is disabled
(`--no-wrap`):

```bash
bootroot-remote bootstrap \
  --openbao-url http://127.0.0.1:8200 \
  --kv-mount secret \
  --service-name edge-remote \
  --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
  --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id \
  --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json \
  --agent-config-path /srv/bootroot/agent.toml \
  --agent-email admin@example.com \
  --agent-server https://stepca.internal:9000/acme/acme/directory \
  --agent-domain trusted.domain \
  --agent-responder-url http://responder.internal:8080 \
  --profile-hostname edge-node-02 \
  --profile-instance-id 101 \
  --profile-cert-path /srv/bootroot/certs/edge-remote.crt \
  --profile-key-path /srv/bootroot/certs/edge-remote.key \
  --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem \
  --summary-json /srv/bootroot/tmp/edge-remote-summary.json \
  --output json
```

`bootroot-remote bootstrap` performs a one-shot pull and apply of the service
configuration bundle (`secret_id`, `eab`, `responder_hmac`, `trust`).
The `remote run command template` printed by `bootroot service add` uses the
`--artifact` flag, so `--agent-server` and `--agent-responder-url` values are
read from the artifact rather than the command line. If the service machine
cannot reach the default localhost endpoints, edit `bootstrap.json` and
replace them with remote-reachable values (e.g., `stepca.internal`,
`responder.internal`) before transferring the artifact.

### 3-4) Post-renew hook (reload style preset)

Use `--reload-style` and `--reload-target` to configure
a post-renew hook that reloads the service after
certificate renewal:

```bash
bootroot service add \
  --service-name edge-proxy \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config /etc/bootroot/agent.toml \
  --cert-path /etc/bootroot/certs/edge-proxy.crt \
  --key-path /etc/bootroot/certs/edge-proxy.key \
  --instance-id 001 \
  --reload-style systemd \
  --reload-target nginx \
  --root-token <OPENBAO_ROOT_TOKEN>
```

This expands into a `[profiles.hooks.post_renew]` entry
in the generated `agent.toml` profile that runs
`systemctl reload nginx` after each successful renewal.
Other preset styles are `sighup` (sends `SIGHUP` via
`pkill`), `docker-restart` (runs `docker restart`), and
`none` (no hook). For full control, use the low-level
flags `--post-renew-command`, `--post-renew-arg`,
`--post-renew-timeout-secs`, and
`--post-renew-on-failure` instead.

After secret_id rotation on the control node, a *running* remote
`bootroot-agent` picks up the new secret_id itself through its fast-poll loop —
no manual delivery is needed. The command below is the **recovery** path only,
for an agent that was offline past its `secret_id_ttl` and whose credential
already expired:

```bash
bootroot-remote apply-secret-id \
  --openbao-url http://127.0.0.1:8200 \
  --kv-mount secret \
  --service-name edge-remote \
  --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
  --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id
```

### 3-5) service update (policy change)

To change per-service `secret_id` policy without re-running
`service add`:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
```

To disable response wrapping for a service:

```bash
bootroot service update --service-name edge-proxy --no-wrap
```

To restore the default wrapping behavior:

```bash
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

After updating policy, apply it on the next rotation:

```bash
bootroot rotate approle-secret-id --service-name edge-proxy
```

## 4) DNS resolution for HTTP-01 validation

`bootroot service add` automatically registers each service's validation FQDN
(`<instance_id>.<service_name>.<hostname>.<domain>`) as a Docker network alias
on the `bootroot-http01` container. This lets step-ca resolve the FQDN to the
responder without any manual configuration.

If `bootroot-http01` is restarted (e.g. `docker compose down` / `up`),
`bootroot infra up` replays all aliases from `state.json` automatically.

For non-Compose environments or when manual resolution is needed, add
`/etc/hosts` entries inside the step-ca container:

```bash
RESPONDER_IP="$(docker inspect -f \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  bootroot-http01)"
docker exec bootroot-ca sh -c \
  "printf '%s %s\n' \"$RESPONDER_IP\" \
  '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
```

## 5) service verify

```bash
bootroot verify --service-name edge-proxy
```

To verify DB connectivity/auth as well:

```bash
bootroot verify --service-name edge-proxy --db-check
```

Sample dialog/output (full):

```text
bootroot verify: summary
- service name: edge-proxy
- result: ok
```

`bootroot verify` performs a one-shot issuance check. For **continuous
renewal**, run bootroot-agent in daemon mode (without `--oneshot`).

## 6) Run services (continuous mode)

“Continuous mode” means the daemon keeps running to renew certificates
periodically, rather than a one-shot verification run.

bootroot-agent runs as a **host daemon** — no per-service OpenBao Agent
and no Docker sidecar. Run one `bootroot-agent` process plus one agent
config per **distinct service**; the `[openbao]` section holds a single
AppRole credential, so distinct services cannot share one `agent.toml`.
Multiple `[[profiles]]` in one config are only for instances of the same
service — update `agent.toml` and reload the daemon when adding such
instances. Configure systemd so the
process restarts automatically (set `Restart=always` or `on-failure`;
see
[Operations > Hardened systemd unit example](operations.md#hardened-systemd-unit-example)).

Use the run command printed by `service add` — `--eab-file` is required
for EAB rotation to apply:

```bash
bootroot-agent --config /etc/bootroot/agent.toml \
  --eab-file /path/to/secrets/services/edge-proxy/eab.json
```

Sample output:

```text
Loaded 1 profile(s).
Issuing certificate for 001.edge-proxy.edge-node-01.trusted.domain
Certificate issued successfully.
```

For an application that runs in a container, the same host daemon writes
the cert/key to a host directory the container bind-mounts; the
`docker-restart` post-renew hook restarts the container after each
renewal (see section 3-2).

## 7) Secret rotation (examples)

bootroot provides rotation commands for **secrets** (step-ca password,
DB credentials, HMAC, AppRole). **Certificate renewal** is handled by
`bootroot-agent`. EAB credentials are not rotated by bootroot: the
bundled OSS step-ca does not support EAB, and for EAB-capable CAs the
operator re-provisions credentials in OpenBao KV directly.

Example that rotates all secrets:

```bash
bootroot rotate stepca-password
bootroot rotate db \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5433/postgres"
bootroot rotate responder-hmac
bootroot rotate openbao-recovery --rotate-root-token

# Rotate every registered service secret_id in one invocation
# (per-service targeting stays available via --service-name)
bootroot rotate approle-secret-id --all-services

# Rotate the infra AppRole secret_ids consumed by the infra OpenBao
# Agents (requires bootroot-infra-rotate-role credentials, not the
# runtime-rotate credential used above)
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  --yes \
  approle-secret-id --infra stepca
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  --yes \
  approle-secret-id --infra responder

# Sync CA trust data to OpenBao and all services
bootroot rotate trust-sync

# Force certificate reissue for a specific service
bootroot rotate force-reissue --service-name edge-proxy

# Force reissue for a remote-bootstrap service and wait for the remote
# agent to apply it (polls completed_at on the OpenBao reissue KV path).
bootroot rotate force-reissue \
  --service-name edge-remote --wait --wait-timeout 90s
```

Rotate OpenBao recovery credentials manually (unseal keys + root token):

```bash
bootroot rotate \
  --openbao-url http://localhost:8200 \
  --root-token "$OPENBAO_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-unseal-keys \
  --rotate-root-token \
  --unseal-key-file ./secure/openbao-unseal-keys.txt \
  --output ./secure/openbao-recovery-rotated.json
```

CA key rotation (intermediate-only):

```bash
bootroot rotate \
  --compose-file docker-compose.yml \
  --openbao-url http://localhost:8200 \
  --auth-mode approle \
  --approle-role-id "$ROTATE_ROLE_ID" \
  --approle-secret-id "$ROTATE_SECRET_ID" \
  --yes \
  ca-key --cleanup
```

CA key rotation (full — root + intermediate):

```bash
bootroot rotate \
  --compose-file docker-compose.yml \
  --openbao-url http://localhost:8200 \
  --auth-mode approle \
  --approle-role-id "$ROTATE_ROLE_ID" \
  --approle-secret-id "$ROTATE_SECRET_ID" \
  --yes \
  ca-key --full --cleanup
```

After CA key rotation, force-reissue certificates for all services:

```bash
bootroot rotate force-reissue --service-name edge-proxy
bootroot rotate force-reissue --service-name web-app
```

Scheduled execution (cron example, script to run all rotations):

```bash
#!/usr/bin/env bash
set -euo pipefail

bootroot rotate stepca-password --yes
bootroot rotate db --yes \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5433/postgres"
bootroot rotate responder-hmac --yes
```

```crontab
# every day at 03:00
0 3 * * * /usr/local/bin/bootroot-rotate-all.sh
```

> Adjust schedules and targets to match your policy.

## 8) Monitoring (examples)

Start monitoring with LAN-only access:

```bash
bootroot monitoring up --profile lan --grafana-admin-password admin
```

Start monitoring with public access:

```bash
bootroot monitoring up --profile public --grafana-admin-password admin
```

Check status:

```bash
bootroot monitoring status
```

Access URLs:

- `lan`: `http://<lan-ip>:3000` (or `http://127.0.0.1:3000` if using default)
- `public`: `http://<public-ip>:3000`

Reset Grafana admin password and restart:

```bash
bootroot monitoring down --reset-grafana-admin-password
bootroot monitoring up --profile lan --grafana-admin-password newpass
```
